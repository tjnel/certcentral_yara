import "pe"

rule MAL_Compromised_Cert_SnipBot_GlobalSign_0BC777F88DDF5F3CE479452F {
   meta:
      description         = "Detects SnipBot with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-07"
      version             = "1.0"

      hash                = "0be3116a3edc063283f3693591c388eec67801cdd140a90c4270679e01677501"
      malware             = "SnipBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ARION LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0b:c7:77:f8:8d:df:5f:3c:e4:79:45:2f"
      cert_thumbprint     = "55AA40DEA5621F0C0FBC8B9DD8066FF2290A7E82"
      cert_valid_from     = "2024-05-07"
      cert_valid_to       = "2025-05-08"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "arion.ooo@rambler.ru"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0b:c7:77:f8:8d:df:5f:3c:e4:79:45:2f"
      )
}
