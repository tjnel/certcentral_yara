import "pe"

rule MAL_Compromised_Cert_Cicada_RAT_GlobalSign_1F02BC9533123645610F5914 {
   meta:
      description         = "Detects Cicada RAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-07"
      version             = "1.0"

      hash                = "65103ed62bf26e5bab1b56756771bc129d2c6ff6a419cab858d29d0ff233bef2"
      malware             = "Cicada RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SCANDI LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1f:02:bc:95:33:12:36:45:61:0f:59:14"
      cert_thumbprint     = "8C502B3B11E89BAA6B9F5C8BC30D248BFCD1E74E"
      cert_valid_from     = "2023-08-07"
      cert_valid_to       = "2024-08-07"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1237700488519"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1f:02:bc:95:33:12:36:45:61:0f:59:14"
      )
}
