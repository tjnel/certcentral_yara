import "pe"

rule MAL_Compromised_Cert_ClearFake_GlobalSign_05B7F83D956379CDF5C31382 {
   meta:
      description         = "Detects ClearFake with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-20"
      version             = "1.0"

      hash                = "82cc0f3f4aa70a8215b62db7ee9deac1c3d4dd27cde25cf56ec2f82ca7d146a9"
      malware             = "ClearFake"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CONG TY TNHH SAN XUAT VA THUONG MAI HUU BANG"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "05:b7:f8:3d:95:63:79:cd:f5:c3:13:82"
      cert_thumbprint     = "96E65313B167FF117658D4143A1B861DFAA76F7D"
      cert_valid_from     = "2024-06-20"
      cert_valid_to       = "2025-06-21"

      country             = "VN"
      state               = "Thai Binh"
      locality            = "Thai Binh"
      email               = "???"
      rdn_serial_number   = "1001266910"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "05:b7:f8:3d:95:63:79:cd:f5:c3:13:82"
      )
}
