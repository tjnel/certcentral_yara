import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_27987C7E3C455F499B18AFD03B3CBBDF {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-30"
      version             = "1.0"

      hash                = "ce8c2fc7e49bc791f10b5022a0d353debb620d11b4f7add4c2215771250b34eb"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Блу Сейл Комодіті\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "27:98:7c:7e:3c:45:5f:49:9b:18:af:d0:3b:3c:bb:df"
      cert_thumbprint     = "949F349032F495EC682A1D6A58D892ED9145A2ED"
      cert_valid_from     = "2023-08-30"
      cert_valid_to       = "2024-08-29"

      country             = "UA"
      state               = "???"
      locality            = "Kyiv"
      email               = "???"
      rdn_serial_number   = "45224266"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "27:98:7c:7e:3c:45:5f:49:9b:18:af:d0:3b:3c:bb:df"
      )
}
