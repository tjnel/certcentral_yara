import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_726DC2955912DC0E6072B40690760BC3 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-11"
      version             = "1.0"

      hash                = "4ecd4fb56d55e34778d10c6a4c3a52531a76b4c3ec6d3436405a81ec87735843"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Brango ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "72:6d:c2:95:59:12:dc:0e:60:72:b4:06:90:76:0b:c3"
      cert_thumbprint     = "5411829A2D9416D61E323279F3AC86F4D78FF5AB"
      cert_valid_from     = "2024-01-11"
      cert_valid_to       = "2025-01-08"

      country             = "DK"
      state               = "Capital Region of Denmark"
      locality            = "Valby"
      email               = "???"
      rdn_serial_number   = "38181297"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "72:6d:c2:95:59:12:dc:0e:60:72:b4:06:90:76:0b:c3"
      )
}
