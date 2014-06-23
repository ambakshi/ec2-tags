package main

import (
	"os"
	"testing"
)

func chk(t *testing.T, tags map[string]string, key string, expected string) {
	tag := tags[key]
	if tag != expected {
		t.Errorf("Expected %s but got %s", tag, expected)
	}
}

func TestEc2Tags(t *testing.T) {
	instance_id := "i-69deb839"

	_, tags, err := Ec2Tags(instance_id)
	if err != nil {
		t.Fatal("Failed to get tags")
	}
	chk(t, tags, "Name", "ops-deploy-003")
	chk(t, tags, "Billing_Code", "ops")
	chk(t, tags, "Owner", "amit.bakshi")
	chk(t, tags, "Hostgroup", "ops-deploy")
}

func TestEc2ByTag(t *testing.T) {
	t.Skip("Not working for some reason")
	t.Logf("Ec2ByTag Hostgroup:ops-deploy")
	instances, err := Ec2ByTag("Hostgroup", "ops-deploy")
	if err != nil {
		t.Fatal("Failed to query Ec2 for hostgroup ops-deploy")
	}
	for _, tags := range instances {
		chk(t, tags, "Name", "ops-deploy-003")
		chk(t, tags, "Billing_Code", "ops")
		chk(t, tags, "Owner", "amit.bakshi")
		chk(t, tags, "Hostgroup", "ops-deploy")
	}
}

func TestSanitize(t *testing.T) {
	if Sanitize("1-2-3") != "1_2_3" {
		t.Fail()
	}
	if Sanitize("1::2::3::") != "1__2__3__" {
		t.Fail()
	}
}

func TestFailAuth(t *testing.T) {
	t.Skip("Skipped due to built in credentials")
	os.Setenv("AWS_CREDENTIAL_FILE", "/tmp/fail")
	os.Setenv("AWS_DEFAULT_PROFILE", "baaaad")
	_, err := getAuth("x", "y")
	if err == nil {
		t.Fail()
	}
}

func TestAuth(t *testing.T) {
	os.Setenv("AWS_CREDENTIAL_FILE", "")
	os.Setenv("AWS_DEFAULT_PROFILE", "")
	_, err := getAuth("", "")
	if err != nil {
		t.Fail()
	}
}
