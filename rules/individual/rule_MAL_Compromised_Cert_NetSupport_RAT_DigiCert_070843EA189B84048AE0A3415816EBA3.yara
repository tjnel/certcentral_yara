import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_DigiCert_070843EA189B84048AE0A3415816EBA3 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-07"
      version             = "1.0"

      hash                = "0d4e1abeba056550ae04d476a81e4f90ac7681845e53d913a8bb802114e814ff"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Resedavide AB"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "07:08:43:ea:18:9b:84:04:8a:e0:a3:41:58:16:eb:a3"
      cert_thumbprint     = "264D284AFAE1598DF4236E990AF033DD761D7A99"
      cert_valid_from     = "2021-12-07"
      cert_valid_to       = "2022-12-02"

      country             = "SE"
      state               = "???"
      locality            = "Stockholm"
      email               = "???"
      rdn_serial_number   = "5592127780"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "07:08:43:ea:18:9b:84:04:8a:e0:a3:41:58:16:eb:a3"
      )
}
