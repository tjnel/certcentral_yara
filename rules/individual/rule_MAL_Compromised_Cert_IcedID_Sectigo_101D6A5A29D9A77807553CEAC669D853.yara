import "pe"

rule MAL_Compromised_Cert_IcedID_Sectigo_101D6A5A29D9A77807553CEAC669D853 {
   meta:
      description         = "Detects IcedID with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-04"
      version             = "1.0"

      hash                = "e70c965ae03c89538c94cc65ada5194c0b129a67e4c5f0eca728965ff4f831ae"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "BIC GROUP LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "10:1d:6a:5a:29:d9:a7:78:07:55:3c:ea:c6:69:d8:53"
      cert_thumbprint     = "BCAF8B48FD451035B0B9307B61FA737F7907E5B2"
      cert_valid_from     = "2022-03-04"
      cert_valid_to       = "2023-03-04"

      country             = "GB"
      state               = "London"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "10:1d:6a:5a:29:d9:a7:78:07:55:3c:ea:c6:69:d8:53"
      )
}
