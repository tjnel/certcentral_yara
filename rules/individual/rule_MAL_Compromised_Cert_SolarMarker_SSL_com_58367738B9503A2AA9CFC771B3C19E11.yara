import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_58367738B9503A2AA9CFC771B3C19E11 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-22"
      version             = "1.0"

      hash                = "fbef401c6a7ad24640f6b6583aa0d0fa02aa895c47ab08e68b0e6e312d1b42a5"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "SLIM DOG SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "58:36:77:38:b9:50:3a:2a:a9:cf:c7:71:b3:c1:9e:11"
      cert_thumbprint     = "BBE2C16616548CFBC0C78789DCB186653DC8DF2E"
      cert_valid_from     = "2023-12-22"
      cert_valid_to       = "2024-12-21"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "0000491343"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "58:36:77:38:b9:50:3a:2a:a9:cf:c7:71:b3:c1:9e:11"
      )
}
