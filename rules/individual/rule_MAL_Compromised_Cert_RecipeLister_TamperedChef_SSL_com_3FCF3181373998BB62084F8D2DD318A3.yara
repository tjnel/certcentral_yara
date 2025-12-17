import "pe"

rule MAL_Compromised_Cert_RecipeLister_TamperedChef_SSL_com_3FCF3181373998BB62084F8D2DD318A3 {
   meta:
      description         = "Detects RecipeLister,TamperedChef with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-25"
      version             = "1.0"

      hash                = "1619bcad3785be31ac2fdee0ab91392d08d9392032246e42673c3cb8964d4cb7"
      malware             = "RecipeLister,TamperedChef"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was downloaded by advertisements for a Recipe application. The recipes contained hidden characters that could be decoded by the application. See the following for more details: https://www.bluevoyant.com/blog/recipelister-a-recipe-for-disaster"

      signer              = "Global Tech Allies ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "3f:cf:31:81:37:39:98:bb:62:08:4f:8d:2d:d3:18:a3"
      cert_thumbprint     = "C9BE49E1CFD42DA1B305344C2D705397CDC5A12B"
      cert_valid_from     = "2025-02-25"
      cert_valid_to       = "2026-02-25"

      country             = "GB"
      state               = "???"
      locality            = "Luton"
      email               = "???"
      rdn_serial_number   = "15440807"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "3f:cf:31:81:37:39:98:bb:62:08:4f:8d:2d:d3:18:a3"
      )
}
