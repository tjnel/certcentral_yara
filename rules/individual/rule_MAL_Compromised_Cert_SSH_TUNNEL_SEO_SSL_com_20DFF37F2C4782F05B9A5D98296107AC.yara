import "pe"

rule MAL_Compromised_Cert_SSH_TUNNEL_SEO_SSL_com_20DFF37F2C4782F05B9A5D98296107AC {
   meta:
      description         = "Detects SSH_TUNNEL_SEO with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-18"
      version             = "1.0"

      hash                = "c16f0bc298ccf19b6b38c8f4741cce81214cc3f0c00e70042ecd98e444bf4675"
      malware             = "SSH_TUNNEL_SEO"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Business Advice & Support LLP"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "20:df:f3:7f:2c:47:82:f0:5b:9a:5d:98:29:61:07:ac"
      cert_thumbprint     = "B972DA26C6ADEF9A4B09F0ADA4C544CC53DA5599"
      cert_valid_from     = "2024-06-18"
      cert_valid_to       = "2025-06-18"

      country             = "GB"
      state               = "England"
      locality            = "Calne"
      email               = "???"
      rdn_serial_number   = "OC429523"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "20:df:f3:7f:2c:47:82:f0:5b:9a:5d:98:29:61:07:ac"
      )
}
