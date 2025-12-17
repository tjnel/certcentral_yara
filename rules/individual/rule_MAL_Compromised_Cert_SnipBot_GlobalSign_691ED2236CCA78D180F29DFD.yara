import "pe"

rule MAL_Compromised_Cert_SnipBot_GlobalSign_691ED2236CCA78D180F29DFD {
   meta:
      description         = "Detects SnipBot with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-06"
      version             = "1.0"

      hash                = "cfb1e3cc05d575b86db6c85267a52d8f1e6785b106797319a72dd6d19b4dc317"
      malware             = "SnipBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "COSMART LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "69:1e:d2:23:6c:ca:78:d1:80:f2:9d:fd"
      cert_thumbprint     = "8c8a043f51bb8d59182fb268c0db2f1b9d876dbe"
      cert_valid_from     = "2023-12-06"
      cert_valid_to       = "2024-11-07"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "69:1e:d2:23:6c:ca:78:d1:80:f2:9d:fd"
      )
}
