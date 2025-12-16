import "pe"

rule MAL_Compromised_Cert_Gozi_Sectigo_00B4F42E2C153C904FDA64C957ED7E1028 {
   meta:
      description         = "Detects Gozi with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-20"
      version             = "1.0"

      hash                = "9e0cfd00991a3d387a78770a7748418b4d0ab978717f84a399d766b19a971df0"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NONO spol. s r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:b4:f4:2e:2c:15:3c:90:4f:da:64:c9:57:ed:7e:10:28"
      cert_thumbprint     = "ED4C50AB4F173CF46386A73226FA4DAC9CADC1C4"
      cert_valid_from     = "2020-10-20"
      cert_valid_to       = "2021-10-20"

      country             = "SK"
      state               = "???"
      locality            = "Bratislava"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:b4:f4:2e:2c:15:3c:90:4f:da:64:c9:57:ed:7e:10:28"
      )
}
