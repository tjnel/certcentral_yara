import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_4C3BDCE63AA1C18EB276CC8FFDF8DE8F {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-02"
      version             = "1.0"

      hash                = "bd55d845fcb90f645c601090498ca056647b91d82e39081e41b15495ffd530ff"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Hunan Kangcai Business Services Partnership Enterprise (Limited)"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4c:3b:dc:e6:3a:a1:c1:8e:b2:76:cc:8f:fd:f8:de:8f"
      cert_thumbprint     = "27281E474CF6D0125D0EC55DD158173D4682226B"
      cert_valid_from     = "2024-02-02"
      cert_valid_to       = "2025-01-28"

      country             = "CN"
      state               = "Hunan"
      locality            = "Changsha"
      email               = "???"
      rdn_serial_number   = "91430103MA4QMCCB7K"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4c:3b:dc:e6:3a:a1:c1:8e:b2:76:cc:8f:fd:f8:de:8f"
      )
}
