import "pe"

rule MAL_Compromised_Cert_CobaltStrike_SSL_com_70AACF510F5C8A893C5104B2DB315633 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-28"
      version             = "1.0"

      hash                = "12c98ce7a4c92244ae122acc5d50745ee3d2de3e02d9b1b8a7e53a7b142f652f"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Rigveda Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "70:aa:cf:51:0f:5c:8a:89:3c:51:04:b2:db:31:56:33"
      cert_thumbprint     = "754AC4AD446D76B2A788453030E6845E7A9EFC33"
      cert_valid_from     = "2023-08-28"
      cert_valid_to       = "2024-08-27"

      country             = "GB"
      state               = "???"
      locality            = "Epping"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "70:aa:cf:51:0f:5c:8a:89:3c:51:04:b2:db:31:56:33"
      )
}
