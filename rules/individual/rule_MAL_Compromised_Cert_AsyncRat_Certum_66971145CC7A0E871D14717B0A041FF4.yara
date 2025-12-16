import "pe"

rule MAL_Compromised_Cert_AsyncRat_Certum_66971145CC7A0E871D14717B0A041FF4 {
   meta:
      description         = "Detects AsyncRat with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-09"
      version             = "1.0"

      hash                = "176d1353a81e0fbf050a917e8bd26a6187f8efe5746d7aec7e24b82e11382337"
      malware             = "AsyncRat"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Open Source Developer, Jun Liu"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "66:97:11:45:cc:7a:0e:87:1d:14:71:7b:0a:04:1f:f4"
      cert_thumbprint     = "7F63BF01D47A36A31C970BF1C4113FA501209234"
      cert_valid_from     = "2024-07-09"
      cert_valid_to       = "2025-07-09"

      country             = "CN"
      state               = "江苏省"
      locality            = "淮安市"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "66:97:11:45:cc:7a:0e:87:1d:14:71:7b:0a:04:1f:f4"
      )
}
