import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_14ECD44C98C3DF27FCC699DC70E32C7A {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-11-02"
      version             = "1.0"

      hash                = "f799e7e81b66cf7d787abc864ed82c3dc5fd2aa95c9f3d24a39c79a3741d37c1"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Daxon Digital Services Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "14:ec:d4:4c:98:c3:df:27:fc:c6:99:dc:70:e3:2c:7a"
      cert_thumbprint     = "84F120783C24B1300ADD782414901503AF2F964A"
      cert_valid_from     = "2022-11-02"
      cert_valid_to       = "2023-10-20"

      country             = "US"
      state               = "Florida"
      locality            = "West Palm Beach"
      email               = "???"
      rdn_serial_number   = "P22000068942"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "14:ec:d4:4c:98:c3:df:27:fc:c6:99:dc:70:e3:2c:7a"
      )
}
