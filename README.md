## lib-dcc - DCC library, use it for internal distribution of the package only

## Suggestions:

- This library is custom implementation of generating dcc checksum in GO, a wrapper over C library 
- before making any changes to code make sure to run following command, this will generate new verison of shared library
  ``
  make clean
  make install
  ``
- Do not change the name of library libdcc.so

## Demonstration:

```go
package main

import (
    "fmt"
    dcc "github.com/DTSL/lib-dcc"
)

func main() {
	html := "X-Mailin-EID:NTQwMzk0MzB%2BaS5rbGVpbkBob3RtYWlsLmZyfjwyMDIwMDcyMjEzMDcuNjMzMzUwMDQ2MjdAc210cC1yZWxheS5tYWlsaW4uZnI%2BfmVtWlsLmZhbWlsZW8uY29t\nTo: i.klein@hotmail.fr\nDate: Wed, 22 Jul 2020 11:07:08 +0000\nSubject: Confirmation d'inscription\nMessage-Id: <0d7398ec-4e64-4b6e-980d-a44f68c6500d@smtp-relay.sendinblue.com>\nOrigin-messageId: <202007221307.63335004627@smtp-relay.mailin.fr>\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\nMIME-Version: 1.0\nX-sib-id: g9mCPC8MHeHJarheS6CxOXJ2uYjG4c25hscyFmYoyu14XdNnMaW8cVS8CTXMwg5F4XbZIAmMDg8xsbNkdK2BEOetJi6wPX-NAFp7a3QjOBiy-BGQt5zOAEdMP-MG1PpgYsWVypD322DcHc055aD-o9r_jfW9QIMLvJaNRot3vNs\nX-CSA-Complaints: whitelist-complaints@eco.de\n\r\nBODY starts here, this is test emailYour work Projects Filters Dashboards People Plans Apps Create Search 9+ 3+ Projects Email Sending email-sending (sprint view) 4 days remainingComplete sprint Board Tools 3rd Jan - 14th Jan - 2022 Show tickets assigned to Regular BluSky Only My Issues Recently Updated Insights TO DO 2 IN PROGRESS 3 CODE IN REVIEW 0 QA IN DEV/STAGING 0 DONE IN STAGING 0 QA IN PROD 1 DONE 2 Dharmendra Yadav2 issues Implement DIC pattern - Fetch Process Consumer Implement DIC pattern TaskMajor priority5 Assignee: Dharmendra Yadav ES 33- specs DCC fingerprint DCC fingerprint in email-sending TaskMajor priority1 Assignee: Dharmendra Yadav ES 512- Dharmendra Yadav4 issues expired-process test coverage improve email-sending test coverage improvement TaskMajor priority3 Assignee: Himanshu Gupta ES 321- handle empty emails records in testmail producer/consumer TaskMajor priority2 Assignee: Himanshu Gupta ES 506- POC DCC fingerprint DCC fingerprint in email-sending TaskMajor priority5 Assignee: Himanshu Gupta ES 513- How to do migration GCP migration TaskMajor priority3 Assignee: Himanshu Gupta ES 509- Sagar Sachdev2 issues ES-501Added Kafka consumers for Sendmail Transarchive Project QA for ES-501 Sub-taskMajor priority Assignee: Sagar Sachdev ES 514- Added Kafka consumers for Sendmail Transarchive Project TaskMajor priority3 Assignee: Sagar Sachdev ES 501-"
	checksum := dcc.ChecksumGenerator(html)
	fmt.Println(checksum)
} //                                                                        main
```
