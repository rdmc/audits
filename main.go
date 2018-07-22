package main

import (
	"fmt"
	"os"

	"github.com/pkg/profile"
)

func main() {

	defer profile.Start(profile.MemProfile).Stop()

	for _, arg := range os.Args[1:] {
		/*	if i == 0 {
				continue
			}
			// print index and value
			//fmt.Println("item", i, "is", arg)
			_ = arg
		*/
		fmt.Printf("Processing file %q ...\n", arg)
		_ = parseBccAuditFile2(arg)
		/*
			file, err := os.Open(arg)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()

			reader := csv.NewReader(file)

			// v v v v v v v v v v v
			//reader.FieldsPerRecord = 17
			//reader.LazyQuotes = false
			reader.ReuseRecord = false
			// ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^

			lin := 0
			lr := make([]string, 20, 40)
			for {
				record, err := reader.Read()
				if err == io.EOF {
					break
				}
				lin++
				stats.cnt++
				if err != nil {
					log.Println("#Error:", err, ", #", lin, ", LINE=", record)
					stats.errors++
					//	fmt.Printf("NEW LEN=%d, OLD LEN %d\n", len(record), len(lr))
					//	for i, v := range record {
					//		fmt.Printf("#[%02d] NEW = %v, \tOLD = %v\n", i, v, lr[i])
					//	}

					continue
					// we can try to parse manualy ?????
					// or we can pipe the original file, to a filter ?????
					// to fix/escape "," comas, """ qotes
				}

				audit, _ := ParseAuditRecord(record)
				_ = audit

				copy(lr, record)
				//fmt.Println(len(record), ":", lin, record)
				//fmt.Println(audit.String())
				//fmt.Println("================================================================================")
			}
		*/
	}
	PrintStats()
}
