import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Sectigo_00BDB99D5ECF8271D48E35F1039C2160EF {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2019-07-09"
      version             = "1.0"

      hash                = "c8425cf994f02784d3f8eeb570b6ac1edc5876908b64b40b532e2534a84a19ad"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Gavrilov Andrei Alekseevich"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:bd:b9:9d:5e:cf:82:71:d4:8e:35:f1:03:9c:21:60:ef"
      cert_thumbprint     = "331F96A1A187723EAA5B72C9D0115C1C57F08B66"
      cert_valid_from     = "2019-07-09"
      cert_valid_to       = "2024-07-08"

      country             = "RU"
      state               = "Sankt-Peterburg"
      locality            = "Sankt-Peterburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:bd:b9:9d:5e:cf:82:71:d4:8e:35:f1:03:9c:21:60:ef"
      )
}
