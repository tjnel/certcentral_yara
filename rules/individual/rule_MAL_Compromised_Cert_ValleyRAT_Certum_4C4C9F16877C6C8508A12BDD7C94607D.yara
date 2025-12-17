import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_4C4C9F16877C6C8508A12BDD7C94607D {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-03"
      version             = "1.0"

      hash                = "43130df9d6c99e0d01470a57e0a21215a9afbb1c9b191e1b86fcb046316de6d1"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiangyang Dianjue Trading Store (Sole Proprietorship)"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "4c:4c:9f:16:87:7c:6c:85:08:a1:2b:dd:7c:94:60:7d"
      cert_thumbprint     = "EDDFDB2DC4308CDCBE96650D7B19F4C7B773D13E"
      cert_valid_from     = "2025-03-03"
      cert_valid_to       = "2026-03-03"

      country             = "CN"
      state               = "Hubei"
      locality            = "Xiangyang"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "4c:4c:9f:16:87:7c:6c:85:08:a1:2b:dd:7c:94:60:7d"
      )
}
