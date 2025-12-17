import "pe"

rule MAL_Compromised_Cert_Carbanak_Comodo_1D275376A1DB6BFEC5179E527E1D3A6B {
   meta:
      description         = "Detects Carbanak with compromised cert (Comodo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2015-12-25"
      version             = "1.0"

      hash                = "8cc02b721683f8b880c8d086ed055006dcf6155a6cd19435f74dd9296b74f5fc"
      malware             = "Carbanak"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Extrusion Machinery Ltd"
      cert_issuer_short   = "Comodo"
      cert_issuer         = "COMODO RSA Code Signing CA"
      cert_serial         = "1d:27:53:76:a1:db:6b:fe:c5:17:9e:52:7e:1d:3a:6b"
      cert_thumbprint     = "9652F7FD06E4EC13C4C04F064B58CFCDC1C605C3"
      cert_valid_from     = "2015-12-25"
      cert_valid_to       = "2016-12-24"

      country             = "GB"
      state               = "London"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "COMODO RSA Code Signing CA" and
         sig.serial == "1d:27:53:76:a1:db:6b:fe:c5:17:9e:52:7e:1d:3a:6b"
      )
}
