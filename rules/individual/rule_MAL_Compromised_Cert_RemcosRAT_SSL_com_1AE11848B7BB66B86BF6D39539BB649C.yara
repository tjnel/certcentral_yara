import "pe"

rule MAL_Compromised_Cert_RemcosRAT_SSL_com_1AE11848B7BB66B86BF6D39539BB649C {
   meta:
      description         = "Detects RemcosRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-16"
      version             = "1.0"

      hash                = "094cb617763cd4a9672c42624f4d665bc0bc0956ad875b134ee29659805ac135"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ОсОО ГлобалГудс Сапплай"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1a:e1:18:48:b7:bb:66:b8:6b:f6:d3:95:39:bb:64:9c"
      cert_thumbprint     = "18B241ECEA51925C92BF1ECB31C076231C9D5790"
      cert_valid_from     = "2025-04-16"
      cert_valid_to       = "2026-04-16"

      country             = "KG"
      state               = "???"
      locality            = "Bishkek"
      email               = "???"
      rdn_serial_number   = "192750-3301-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1a:e1:18:48:b7:bb:66:b8:6b:f6:d3:95:39:bb:64:9c"
      )
}
