import "pe"

rule MAL_Compromised_Cert_Fakebat_Certificate_SSL_com_6CD23039DFDA4B9363F3666113C2CBC8 {
   meta:
      description         = "Detects Fakebat_Certificate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-18"
      version             = "1.0"

      hash                = "d0db968846f45699ee000f88f208b290be4ce116126164c3644dd413859b08fd"
      malware             = "Fakebat_Certificate"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Fta Engineers Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6c:d2:30:39:df:da:4b:93:63:f3:66:61:13:c2:cb:c8"
      cert_thumbprint     = "ED6EBDA8E7450F2F6C5181FA27EA5A7865080696"
      cert_valid_from     = "2024-05-18"
      cert_valid_to       = "2025-05-18"

      country             = "GB"
      state               = "England"
      locality            = "Brentford"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6c:d2:30:39:df:da:4b:93:63:f3:66:61:13:c2:cb:c8"
      )
}
