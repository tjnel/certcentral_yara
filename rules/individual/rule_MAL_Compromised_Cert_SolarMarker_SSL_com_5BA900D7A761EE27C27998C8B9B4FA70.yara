import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_5BA900D7A761EE27C27998C8B9B4FA70 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-09-14"
      version             = "1.0"

      hash                = "394fa8af1348cbcf3d9beae6dc8b6afb24c6b96bcc3be52601a5b84f9adf007c"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "OOO LEVELAP"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5b:a9:00:d7:a7:61:ee:27:c2:79:98:c8:b9:b4:fa:70"
      cert_thumbprint     = "EDEBF26E6CAD49A8F48A11EFF6BFC13266FF6872"
      cert_valid_from     = "2021-09-14"
      cert_valid_to       = "2022-09-14"

      country             = "RU"
      state               = "???"
      locality            = "St. Petersburg"
      email               = "???"
      rdn_serial_number   = "1117847087819"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5b:a9:00:d7:a7:61:ee:27:c2:79:98:c8:b9:b4:fa:70"
      )
}
