import "pe"

rule MAL_Compromised_Cert_IcedID_Sectigo_00A73B6D821F84DB4451D6EEDD62C42848 {
   meta:
      description         = "Detects IcedID with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-01-14"
      version             = "1.0"

      hash                = "15b65ccfeced9c5ae3359db9d3a0e68ad0201912b65a0578d5dd7a0f7f7b387d"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "Mht Holding Vinderup ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:a7:3b:6d:82:1f:84:db:44:51:d6:ee:dd:62:c4:28:48"
      cert_thumbprint     = "ECA61AD880741629967004BFC40BF8DF6C9F0794"
      cert_valid_from     = "2021-01-14"
      cert_valid_to       = "2022-01-14"

      country             = "DK"
      state               = "???"
      locality            = "Vinderup"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:a7:3b:6d:82:1f:84:db:44:51:d6:ee:dd:62:c4:28:48"
      )
}
