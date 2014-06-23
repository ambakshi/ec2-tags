package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdmob/goamz/aws"
	"github.com/crowdmob/goamz/ec2"
)

const (
	FmtPuppet = iota
	FmtTsv
	FmtShell
	FmtJson
)

var (
	keyId          string
	secretId       string
	instanceId     string
	prefix         string
	tagPrefix      string
	instancePrefix string
	instanceInfo   bool // include extra info on the instance like the ip
	puppet         bool // the next bools are mutually exclusive
	shell          bool
	tsv            bool
	jason          bool
	version        bool
	declExport     bool
	Version        string
	BuildNumber    string
	GitCommit      string
)

type TagFmtFunc func(name, value string) string
type TagInfo struct {
	name, value string
	isTag       bool
}

func init() {
	flag.StringVar(&instanceId, "instance_id", "", "instance id (ex: i-69deb839)")
	flag.StringVar(&keyId, "key_id", "", "Access key ID")
	flag.StringVar(&prefix, "prefix", "", "Variable prefix")
	flag.StringVar(&tagPrefix, "tag_prefix", "ec2_tag_", "Prefix tags with this string")
	flag.StringVar(&instancePrefix, "instance_prefix", "ec2_", "Prefix instance info with this string")
	flag.StringVar(&secretId, "secret_key", "", "Secret key ID.")
	flag.BoolVar(&puppet, "p", false, "Puppet format (like facter -p)")
	flag.BoolVar(&shell, "s", false, "Shell format")
	flag.BoolVar(&tsv, "t", false, "Tsv format")
	flag.BoolVar(&jason, "j", false, "Json format")
	flag.BoolVar(&instanceInfo, "i", false, "Include local instance information")
	flag.BoolVar(&declExport, "e", false, "Emit variables prefixed with 'export'")
	flag.BoolVar(&version, "v", false, "Show verison information")
	flag.Parse()
}

func findTag(tags []ec2.Tag, name string) string {
	for _, v := range tags {
		if v.Key == name {
			return v.Value
		}
	}
	return "None"
}

func getAuth(keyId, secretId string) (aws.Auth, error) {
	auth, err := aws.GetAuth(keyId, secretId, "", time.Time{})
	if err == nil {
		return auth, nil
	}
	awsCreds := os.Getenv("AWS_CREDENTIAL_FILE")
	if awsCreds == "" {
		for _, config := range []string{
			filepath.Join(os.Getenv("HOME"), ".aws", "credentials"),
			filepath.Join(os.Getenv("HOME"), ".aws", "config")} {
			if file, err := os.Open(config); err != nil {
				file.Close()
				awsCreds = config
				break
			}
		}
	}
	awsProfile := os.Getenv("AWS_DEFAULT_PROFILE")
	auth, err = aws.CredentialFileAuth(
		awsCreds,
		awsProfile,
		1800,
	)
	if err == nil {
		return auth, nil
	}
	return auth, err
}

func Sanitize(str string) string {
	return strings.Replace(
		strings.Replace(str,
			"-", "_", -1),
		":", "_", -1)
}

// Query EC2 for the given instance_id and gather
// all the tags into a map of strings -> string
func Ec2Tags(instance_id string) (*ec2.Instance, map[string]string, error) {
	auth, err := getAuth(keyId, secretId)
	if err != nil {
		if keyId != "" || secretId != "" {
			log.Printf("Invalid -key_id or -secret_key flag.\n")
		}
		return nil, nil, err
	}
	conn := ec2.New(auth, aws.Regions[aws.InstanceRegion()])
	iresp, err := conn.DescribeInstances([]string{instance_id}, nil)
	if err != nil {
		log.Printf("Failed to describe instances: %s\n", err)
		return nil, nil, err
	}
	tags := make(map[string]string)
	for _, iresv := range iresp.Reservations {
		for _, inst := range iresv.Instances {
			for _, tag := range inst.Tags {
				k := tag.Key
				tags[k] = tag.Value
			}
			// There should only be one instance returned
			return &inst, tags, nil
		}
	}
	return nil, nil, errors.New("Unreachable code")
}

func Ec2ByTag(key, value string) (map[string]map[string]string, error) {
	auth, err := getAuth(keyId, secretId)
	if err != nil {
		return nil, err
	}
	conn := ec2.New(auth, aws.USWest2)
	filter := ec2.NewFilter()
	filter.Add("instance-state-name", "running")
	filter.Add(fmt.Sprintf("tag:%s", key), value)
	iresp, err := conn.DescribeInstances(nil, filter)
	if err != nil {
		return nil, err
	}
	instance_tags := make(map[string]map[string]string)
	for _, iresv := range iresp.Reservations {
		for _, inst := range iresv.Instances {
			tags := make(map[string]string)
			for _, t := range inst.Tags {
				tags[t.Key] = t.Value
			}
			instance_tags[inst.InstanceId] = tags
			return instance_tags, nil
		}
	}
	return nil, nil
}

func main() {
	// The default is puppet and we also mimic facter
	// by supporting -p
	if version {
		log.Printf("ec2-tags %s.%s (%s)\n", Version, BuildNumber, GitCommit)
		os.Exit(0)
	}
	format := FmtPuppet
	if puppet {
		format = FmtPuppet
	} else if tsv {
		format = FmtTsv
	} else if shell {
		format = FmtShell
	} else if jason {
		format = FmtJson
	}

	conv := map[string]map[int]string{
		"InstanceId": {
			FmtPuppet: "instance_id",
			FmtShell:  "INSTANCE_ID",
		},
		"InstanceType": {
			FmtPuppet: "instance_type",
			FmtShell:  "INSTANCE_TYPE",
		},
		"PrivateIpAddress": {
			FmtPuppet: "local_ipv4",
			FmtShell:  "EC2_LOCAL_IPV4",
		},
		"PublicIpAddress": {
			FmtPuppet: "public_ipv4",
			FmtShell:  "EC2_PUBLIC_IPV4",
		},
		"Region": {
			FmtPuppet: "region",
			FmtShell:  "AWS_DEFAULT_REGION",
		},
	}

	fmtFunc := func(emit chan *TagInfo, done chan bool) {
		var pname string
		var ok bool
		d := make(map[string]string)
		for tagInfo := range emit {
			name, value, isTag := tagInfo.name, tagInfo.value, tagInfo.isTag
			if pname, ok = conv[name][format]; !ok {
				pname = name
			}
			switch format {
			case FmtPuppet:
				if isTag {
					fmt.Printf("%s%s%s=%s\n", prefix, tagPrefix, strings.ToLower(Sanitize(pname)), value)
				} else {
					fmt.Printf("%s%s%s=%s\n", prefix, instancePrefix, pname, value)
				}
			case FmtTsv:
				fmt.Printf("%s%-30s\t%s\n", prefix, pname, value)
			case FmtShell:
				if declExport {
					fmt.Printf("export %s%s='%s'\n", prefix, strings.ToUpper(Sanitize(pname)), value)
				} else {
					fmt.Printf("%s%s='%s'\n", prefix, strings.ToUpper(Sanitize(pname)), value)
				}
			case FmtJson:
				d[pname] = value // buffer the map so we can MarshalJson
			default:
				fmt.Printf("%s%s=%s\n", prefix, pname, value)
			}
		}
		done <- true
	}
	thisInstanceId := aws.InstanceId()
	if instanceId == "" {
		instanceId = thisInstanceId
	}

	if instanceId == "unknown" {
		log.Fatal("Must specify -instance_id")
	}

	tagFunc := func(tags map[string]string, emit chan *TagInfo) {
		for name, value := range tags {
			emit <- &TagInfo{
				name:  name,
				value: value,
				isTag: true,
			}
		}
	}
	ec2Info, tags, err := Ec2Tags(instanceId)
	if err != nil {
		log.Fatalf("Failed to get tags for %s: %s\n", instanceId, err)
	}
	emit, done := make(chan *TagInfo), make(chan bool)

	if format == FmtJson {
		if buf, err := json.MarshalIndent(map[string]interface{}{
			"instanceInfo": ec2Info,
			"instanceTags": tags},
			"", "  "); err == nil {
			os.Stdout.Write(buf)
		}
		done <- true
	} else {
		go fmtFunc(emit, done)
		tagFunc(tags, emit)
	}

	// Include this instances's info
	if instanceInfo {
		if instanceId == thisInstanceId {
			emit <- &TagInfo{"InstanceId", thisInstanceId, false}
			emit <- &TagInfo{"InstanceType", aws.InstanceType(), false}
			emit <- &TagInfo{"PrivateIpAddress", aws.ServerLocalIp(), false}
			emit <- &TagInfo{"PublicIpAddress", aws.ServerPublicIp(), false}
			emit <- &TagInfo{"Region", aws.InstanceRegion(), false}
		} else {
			emit <- &TagInfo{"InstanceId", instanceId, false}
			emit <- &TagInfo{"InstanceType", ec2Info.InstanceType, false}
			emit <- &TagInfo{"PrivateIpAddress", ec2Info.PrivateIPAddress, false}
			emit <- &TagInfo{"PublicIpAddress", ec2Info.IPAddress, false}
			emit <- &TagInfo{"Region", "us-east-1", false}
		}
	}
	close(emit)
	<-done
}
