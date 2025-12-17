import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_0C7C3D057E97CA0CB7A00DA10EF2F477 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-26"
      version             = "1.0"

      hash                = "bd71ab909ad6fa9c57c00d0d31c721d55983da819b9c09da78f91a0658df9b41"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "GREEN ENTERPRISE SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0c:7c:3d:05:7e:97:ca:0c:b7:a0:0d:a1:0e:f2:f4:77"
      cert_thumbprint     = "5FF0B85D1650C4CD4BBF44134F846DFCFB12B769"
      cert_valid_from     = "2024-01-26"
      cert_valid_to       = "2025-01-25"

      country             = "PL"
      state               = "Lower Silesian Voivodeship"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "0000564145"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0c:7c:3d:05:7e:97:ca:0c:b7:a0:0d:a1:0e:f2:f4:77"
      )
}
