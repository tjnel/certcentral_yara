import "pe"

rule MAL_Compromised_Cert_OysterLoader_SSL_com_0268598BAEB054A09457D976E86EF28B {
   meta:
      description         = "Detects OysterLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-05"
      version             = "1.0"

      hash                = "0f680169d5eaab7cebda7b323c59518b31d70efe2a8a1b759f0698d5f918dd9d"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "BKM PROPERTY MANAGERS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "02:68:59:8b:ae:b0:54:a0:94:57:d9:76:e8:6e:f2:8b"
      cert_thumbprint     = "57D7488CD8482F410D004C73FDEB89838423E9D7"
      cert_valid_from     = "2025-09-05"
      cert_valid_to       = "2026-09-05"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "02:68:59:8b:ae:b0:54:a0:94:57:d9:76:e8:6e:f2:8b"
      )
}
