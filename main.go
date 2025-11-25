package main

import (
	"bufio"
	"compress/bzip2"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/seancfoley/ipaddress-go/ipaddr"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"

	mrt "github.com/jackyyf/go-mrt"
	"github.com/schollz/progressbar/v3"
)

const (
	versionString = "0.1.0"
)

var (
	// Output filename
	output string
	// Output file
	outFile *os.File
	// Lookup ASNs for IP addresses
	asnLookup bool
	// Enable verbose output
	verbose bool
	// Print version and exit
	version bool
	// Write JSON
	jsonOutput bool
	// RIB files to read
	ribFiles []string
	// IP address file
	file string
	// Tries for v4 and v6
	v4Trie = ipaddr.Trie[*ipaddr.IPAddress]{}
	v6Trie = ipaddr.Trie[*ipaddr.IPAddress]{}
	// Maps for v4 and v6 prefixes to ASN
	v4PrefixMap = make(map[string]int)
	v6PrefixMap = make(map[string]int)
	// Maps for v4 and v6 prefixes that map to multiple ASNs
	v4MultiASNMap = make(map[string]map[int]struct{})
	v6MultiASNMap = make(map[string]map[int]struct{})
	// Default routes for v4 and v6
	v4Default = ipaddr.NewIPAddressString("0.0.0.0/0").GetAddress()
	v6Default = ipaddr.NewIPAddressString("::/0").GetAddress()
	// Keep track of ASN data so no need to requery the same data
	asnData = make(map[int]ASNData)
	// WaitGroup for reading RIB files
	wg sync.WaitGroup
)

// ASNData is a struct to hold ASN data (CC, RIR, and AS name)
type ASNData struct {
	CC   string `json:"cc,omitempty"`
	RIR  string `json:"rir,omitempty"`
	Name string `json:"name,omitempty"`
}

// Record keeps track of the IP address, prefix, and ASN, along with
// ASN Data from Team Cymru
type Record struct {
	IP     string `json:"ip"`
	Prefix string `json:"prefix"`
	ASN    int    `json:"asn"`
	ASNData
}

// Converts to []int
func keysFromMap(m map[int]struct{}) []int {
	keys := make([]int, 0, len(m))

	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

// queryASN data makes a DNS query to Team Cymru to get ASN data like ASN name,
// RIR, and country code
// This only happens if you use the -a flag
func queryASNData(asn int) ASNData {

	// If we already have the data, return it without doing the DNS query
	if data, ok := asnData[asn]; ok {
		return data
	}

	data := ASNData{}

	// Do the DNS query
	queryString := fmt.Sprintf("AS%d.asn.cymru.com", asn)
	txt, err := net.LookupTXT(queryString)
	if err != nil {
		log.Errorf("Error querying DNS for %s: %s", queryString, err)
		return data
	}

	// Parse the response
	// EX: [11172 | MX | lacnic | 1998-05-05 | Alestra, S. de R.L. de C.V., MX]

	resp := txt[0]
	split := strings.Split(resp, " | ")
	if len(split) != 5 {
		log.Errorf("Error parsing response from %s: %s", queryString, resp)
		return data
	}

	data.CC = split[1]
	data.RIR = split[2]
	data.Name = split[4]

	return data

}

// Read the RIB from a file, populating the v4 and v6 tries & maps
func readRIB(file string) {

	log.Infof("Reading RIB from file %s", file)

	fp, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer fp.Close()
	fz := bzip2.NewReader(fp)
	mr := mrt.NewReader(fz)

	defer func(fname string) {
		log.Println("Done processing", fname)
		if x := recover(); x != nil {
			log.Printf("run time panic: %v, processing ended early", x)
		}
	}(file)

	ctr := 0
	for {

		// iterate through the MRT records

		record, err := mr.Next()

		// Increment the counter
		ctr++
		if ctr%100000 == 0 {
			log.Infof("Read %d records from file %s", ctr, file)
		}

		// If we're at the end of the file, break
		if record == nil {
			log.Infof("Read all records from file %s", file)
			break
		}

		if err != nil {
			log.Errorf("Error reading record: %s", err)
			continue
		}

		subtype := record.Subtype()

		// Bail if it's not a v4/v6 unicast RIB entry
		if subtype != mrt.TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST && subtype != mrt.TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_UNICAST {
			continue
		}

		ribtable := record.(*mrt.TableDumpV2RIB)
		prefix := ribtable.Prefix.String()

		// Get the origin ASN
		originASN := -1
		for i := 0; i < len(ribtable.RIBEntries); i++ {
			entry := ribtable.RIBEntries[i]
			for j := 0; j < len(entry.BGPAttributes); j++ {
				attr := entry.BGPAttributes[j]

				if attr.TypeCode == 2 {
					asPath := attr.Value.(mrt.BGPPathAttributeASPath)
					asPathSegment := asPath[0]

					peerOriginASN, _ := strconv.Atoi(asPathSegment.Value[len(asPathSegment.Value)-1].String())
					if originASN == -1 {
						originASN = peerOriginASN
					}

				}
			}
		}

		// if we have a valid ASN, populate the trie and map with the route
		if originASN != -1 {

			addr := ipaddr.NewIPAddressString(prefix).GetAddress()

			// skip default routes
			if addr.Equal(v4Default) || addr.Equal(v6Default) {
				continue
			} else if addr.IsIPv4() {
				v4Trie.Add(addr)
				if _, ok := v4MultiASNMap[prefix]; !ok {
					v4MultiASNMap[prefix] = make(map[int]struct{})
				}

				for _, entry := range ribtable.RIBEntries { //iterate through each RIB entry
					for _, attr := range entry.BGPAttributes { //iterate through each RIB entry's BGP attributes
						if attr.TypeCode == 2 { //if the BGP attribute is of type 2 (the as path attribute)
							asPath := attr.Value.(mrt.BGPPathAttributeASPath)
							if len(asPath) > 0 {
								asPathSegment := asPath[0]
								if len(asPathSegment.Value) > 0 {
									peerOriginASN, _ := strconv.Atoi(asPathSegment.Value[len(asPathSegment.Value)-1].String())
									v4MultiASNMap[prefix][peerOriginASN] = struct{}{}

									// Record first ASN in v4PrefixMap for normal lookups
									if _, exists := v4PrefixMap[prefix]; !exists {
										v4PrefixMap[prefix] = peerOriginASN
									}
								}
							}
						}
					}
				}
			} else if addr.IsIPv6() {
				v6Trie.Add(addr)
				if _, ok := v6MultiASNMap[prefix]; !ok {
					v6MultiASNMap[prefix] = make(map[int]struct{})
				}

				for _, entry := range ribtable.RIBEntries {
					for _, attr := range entry.BGPAttributes {
						if attr.TypeCode == 2 {
							asPath := attr.Value.(mrt.BGPPathAttributeASPath)
							if len(asPath) > 0 {
								asPathSegment := asPath[0]
								if len(asPathSegment.Value) > 0 {
									peerOriginASN, _ := strconv.Atoi(asPathSegment.Value[len(asPathSegment.Value)-1].String())
									v6MultiASNMap[prefix][peerOriginASN] = struct{}{}

									if _, exists := v6PrefixMap[prefix]; !exists {
										v6PrefixMap[prefix] = peerOriginASN
									}
								}
							}
						}
					}
				}
			} else {
				log.Errorf("Unknown IP address type: %s", addr)
			}

		}
	}
}

// readFile reads a file of IPs and looks up the prefix and ASN for each IP
// outputs results to stdout or a file according to runtime flags
func readFile(file string, multiASNWriter *bufio.Writer) {

	f, err := os.Open(file)
	if err != nil {
		log.Fatal("Error opening file: ", err)
	}
	defer f.Close()

	fileInfo, _ := f.Stat()
    bar := progressbar.DefaultBytes(fileInfo.Size(), "Processing IPs")

	// Read the file line by line
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		bar.Add(len(scanner.Bytes()) + 1)

		// Create a new record
		record := Record{}

		// Get the IP address
		ip := scanner.Text()
		addr := ipaddr.NewIPAddressString(ip).GetAddress()

		prefix_string := "N/A"
		ASN := -1

		// Look up the IP address in the v4 and v6 tries
		if addr.IsIPv4() {
			prefix := v4Trie.LongestPrefixMatch(addr)
			if prefix != nil {
				prefix_string = prefix.String()
				ASN = v4PrefixMap[prefix.String()]

				// Get all ASNs for this prefic
				asns := v4MultiASNMap[prefix_string]
				if len(asns) > 1 {
					asnsSlice := keysFromMap(asns)                      // converts to []int
					asnsStrSlice := make([]string, len(asnsSlice))      // converts to []string

					for i, asn := range asnsSlice {
						asnsStrSlice[i] = strconv.Itoa(asn)
					}

					multiASNWriter.WriteString(fmt.Sprintf("%v,%v,%v\n", ip, prefix_string, strings.Join(asnsStrSlice, ",")))
				}
			}
		} else if addr.IsIPv6() {
			prefix := v6Trie.LongestPrefixMatch(addr)
			if prefix != nil {
				prefix_string = prefix.String()
				ASN = v6PrefixMap[prefix.String()]

				// Get all ASNs for this prefix
				asns := v6MultiASNMap[prefix_string]
				if len(asns) > 1 {
					asnsSlice := keysFromMap(asns)                       // []int
					asnsStrSlice := make([]string, len(asnsSlice))      // []string

					for i, asn := range asnsSlice {
						asnsStrSlice[i] = strconv.Itoa(asn)
					}

					multiASNWriter.WriteString(fmt.Sprintf("%v,%v,%v\n", ip, prefix_string, strings.Join(asnsStrSlice, ",")))
				}
			}
		} else {
			log.Errorf("Unknown IP address type: %s", addr)
		}

		/* Do we need to resolve ASN data? */
		if asnLookup && ASN != -1 {
			// query the ASN data
			record.ASNData = queryASNData(ASN)
		}

		/* Are we outputting JSON? */
		if jsonOutput {
			//marshal json
			record.IP = ip
			record.Prefix = prefix_string
			record.ASN = ASN
			jsonData, err := json.Marshal(record)
			if err != nil {
				log.Fatal("Error marshalling JSON: ", err)
			}

			if outFile != nil {
				outFile.WriteString(string(jsonData) + "\n")
			} else {
				fmt.Println(string(jsonData))
			}

		} else {
			/* Or plain text? */
			if outFile != nil {
				outFile.WriteString(fmt.Sprintf("%v\t%v\t%v\t%v\t%v\t%v\n", ip, prefix_string, ASN, record.CC, record.RIR, record.Name))
			} else {
				fmt.Printf("%v\t%v\t%v\t%v\t%v\t%v\n", ip,
					prefix_string, ASN, record.CC, record.RIR, record.Name)
			}
		}
	}
}

func init() {

	// Commandline flags
	flag.StringVarP(&output, "output", "o", "", "Output filename")
	flag.BoolVarP(&asnLookup, "asn", "a", false, "Lookup ASNs for IP addresses")
	flag.BoolVarP(&jsonOutput, "json", "j", false, "Output in JSON format")
	flag.StringVarP(&file, "file", "f", "", "IP file to read")
	flag.StringSliceVarP(&ribFiles, "ribFile", "i", []string{}, "RIB files to read")
	flag.BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	flag.BoolVarP(&version, "version", "V", false, "Print version and exit")
	flag.Parse()

	if version {
		fmt.Printf("ip-enricher version %v\n", versionString)
		os.Exit(0)
	}

	// Check loglevel
	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	// Check for required flags
	if file == "" {
		log.Fatal("You must specify a file from which to read")
	}

	// Touch the output file
	if output != "" {
		var err error
		outFile, err = os.Create(output)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func main() {

	// Read the RIB files in parallel
	log.Debugf("Reading %v files\n", len(ribFiles))
	for _, file := range ribFiles {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			readRIB(file)
		}(file)
	}

	// Wait for all the RIB files to be read
	wg.Wait()
	log.Infoln("All RIB files read; processing IP file")

	multiASNFile, err := os.Create("multi_asn.txt")
	if err != nil {
		log.Fatal("Error creating multi-ASN file: ", err)
	}
	defer multiASNFile.Close()

	multiASNWriter := bufio.NewWriter(multiASNFile)
	defer func() {
		multiASNWriter.Flush()
		multiASNFile.Close()
	}()

	if file != "" {
		// read the IP file
		readFile(file, multiASNWriter)
	}

	log.Infoln("Completed")

}
