import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_SSL_com_53A4AF566690F74B15A2232F7B01CD61 {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-24"
      version             = "1.0"

      hash                = "acfa8e673b641ed1be17dff41f52589605abbd3afe305a1580b3c8977e90a7fa"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Advik Tech Corporation"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "53:a4:af:56:66:90:f7:4b:15:a2:23:2f:7b:01:cd:61"
      cert_thumbprint     = "9A1CBD2C7831CC8CD56298B01189AF437E0B1673"
      cert_valid_from     = "2024-12-24"
      cert_valid_to       = "2025-12-24"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Surrey"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "53:a4:af:56:66:90:f7:4b:15:a2:23:2f:7b:01:cd:61"
      )
}
