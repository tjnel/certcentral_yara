import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_45948EF79A0B586E27414708C0BDDD2A {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-15"
      version             = "1.0"

      hash                = "817debed45f7f3e0e95da4df3476b58ba0dc3ff7552473c66abd94646fddc962"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "R J DATSON LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "45:94:8e:f7:9a:0b:58:6e:27:41:47:08:c0:bd:dd:2a"
      cert_thumbprint     = "7C27F48DEBABD296AF63311503E75866E788A76F"
      cert_valid_from     = "2023-09-15"
      cert_valid_to       = "2024-09-14"

      country             = "GB"
      state               = "???"
      locality            = "Newmarket"
      email               = "???"
      rdn_serial_number   = "08960413"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "45:94:8e:f7:9a:0b:58:6e:27:41:47:08:c0:bd:dd:2a"
      )
}
