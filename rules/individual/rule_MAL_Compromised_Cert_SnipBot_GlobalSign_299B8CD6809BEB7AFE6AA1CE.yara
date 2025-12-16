import "pe"

rule MAL_Compromised_Cert_SnipBot_GlobalSign_299B8CD6809BEB7AFE6AA1CE {
   meta:
      description         = "Detects SnipBot with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-15"
      version             = "1.0"

      hash                = "57e59b156a3ff2a3333075baef684f49c63069d296b3b036ced9ed781fd42312"
      malware             = "SnipBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CC Byg og Udlejning ApS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "29:9b:8c:d6:80:9b:eb:7a:fe:6a:a1:ce"
      cert_thumbprint     = "01CC86D610C1DBA8C070137B54AE0791EF804419"
      cert_valid_from     = "2024-03-15"
      cert_valid_to       = "2025-03-16"

      country             = "DK"
      state               = "Aalborg"
      locality            = "Vodskov"
      email               = "anders.lykke@ccbu.dk"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "29:9b:8c:d6:80:9b:eb:7a:fe:6a:a1:ce"
      )
}
