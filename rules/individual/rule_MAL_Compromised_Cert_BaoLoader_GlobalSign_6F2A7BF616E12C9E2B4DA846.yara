import "pe"

rule MAL_Compromised_Cert_BaoLoader_GlobalSign_6F2A7BF616E12C9E2B4DA846 {
   meta:
      description         = "Detects BaoLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-03"
      version             = "1.0"

      hash                = "00151cc770d6add3501a7b8cd7815858637d3fe6a0cb7a78fe98a1487cae2f83"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "ASTRAL MEDIA INC."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6f:2a:7b:f6:16:e1:2c:9e:2b:4d:a8:46"
      cert_thumbprint     = "EA67166323EDD57B9222B169F871A7E6E6C5ED02"
      cert_valid_from     = "2023-05-03"
      cert_valid_to       = "2026-05-03"

      country             = "PA"
      state               = "Panama"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704413"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6f:2a:7b:f6:16:e1:2c:9e:2b:4d:a8:46"
      )
}
