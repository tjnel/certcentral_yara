import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_0582253D22D291481B75770C1556C56F {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-14"
      version             = "1.0"

      hash                = "4ceb4a501721f0277072a14220ff435eecedee9930b150adf11057603cf08842"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Open Source Developer, Hao Chen"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "05:82:25:3d:22:d2:91:48:1b:75:77:0c:15:56:c5:6f"
      cert_thumbprint     = "F5EAE4A53268644837FEED29FED03925523B7005"
      cert_valid_from     = "2025-06-14"
      cert_valid_to       = "2026-06-14"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Hanyuan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "05:82:25:3d:22:d2:91:48:1b:75:77:0c:15:56:c5:6f"
      )
}
