import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_12248CFBA203C55278C33B413A81FFB3 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-05"
      version             = "1.0"

      hash                = "fce7f7ad1d7b17e7106639ca23cc49d2cf642bcea024d8ba838f3f559c99e34c"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Open Source Developer, Yu Zeng"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "12:24:8c:fb:a2:03:c5:52:78:c3:3b:41:3a:81:ff:b3"
      cert_thumbprint     = "E5D9BC152B169F444E270B9FAA3AF9C3F451AB46"
      cert_valid_from     = "2025-08-05"
      cert_valid_to       = "2026-08-05"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Jintang"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "12:24:8c:fb:a2:03:c5:52:78:c3:3b:41:3a:81:ff:b3"
      )
}
