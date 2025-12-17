import "pe"

rule MAL_Compromised_Cert_IcedID_Sectigo_3FD3661533EEF209153C9AFEC3BA4D8A {
   meta:
      description         = "Detects IcedID with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-04"
      version             = "1.0"

      hash                = "3fca3f2d46add510a32d81b2ba8b4a5f30fc8ec25eca34175405bf5580a1bec3"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "SFB Regnskabsservice ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "3f:d3:66:15:33:ee:f2:09:15:3c:9a:fe:c3:ba:4d:8a"
      cert_thumbprint     = "20DDD23F53E1AC49926335EC3E685A515AB49252"
      cert_valid_from     = "2021-03-04"
      cert_valid_to       = "2022-03-04"

      country             = "DK"
      state               = "Nordjylland"
      locality            = "Skørping"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "3f:d3:66:15:33:ee:f2:09:15:3c:9a:fe:c3:ba:4d:8a"
      )
}
