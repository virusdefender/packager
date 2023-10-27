package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"github.com/virusdefender/goutils"
	"github.com/virusdefender/goutils/buildinfo"
	"github.com/virusdefender/packager"
	"os"
	"strings"
)

func main() {
	app := cli.NewApp()
	app.Name = "packager"
	app.Usage = "package tool"
	app.Version = fmt.Sprintf("version %s, commit: %s", buildinfo.Version, buildinfo.GitCommit)
	app.Commands = []*cli.Command{
		{
			Name:  "gen-cert",
			Usage: "生成证书",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "ca-cert",
					Value: "./ca.crt",
				},
				&cli.StringFlag{
					Name:  "ca-key",
					Value: "./ca.key",
				},
				&cli.StringFlag{
					Name:  "end-cert",
					Value: "./end.crt",
				},
				&cli.StringFlag{
					Name:  "end-key",
					Value: "./end.key",
				},
				&cli.StringFlag{
					Name:     "common-name",
					Required: true,
				},
			},
			Action: func(c *cli.Context) error {
				caCertPath := c.String("ca-cert")
				caKeyPath := c.String("ca-key")
				endCertPath := c.String("end-cert")
				endKeyPath := c.String("end-key")
				if goutils.FileExists(caCertPath) != goutils.FileExists(caKeyPath) {
					return fmt.Errorf("ca cert and key must both exist or not exist")
				}
				if goutils.FileExists(endKeyPath) || goutils.FileExists(endCertPath) {
					return fmt.Errorf("end cert and key must not exist")
				}

				var rootPrivateKey *rsa.PrivateKey
				var rootCertificate *x509.Certificate
				var err error

				if goutils.FileExists(caCertPath) {
					fmt.Println("ca cert and key exists")
					rootPrivateKey, rootCertificate, err = packager.LoadKeyAndCertificateFromFile(caKeyPath, caCertPath)
					if err != nil {
						return err
					}
				} else {
					fmt.Println("ca cert and key not exist, generating...")
					rootPrivateKey, rootCertificate, err = packager.GenerateRoot()
					if err != nil {
						return err
					}
					err = packager.DumpKeyAndCertificateToFile(caKeyPath, caCertPath, rootPrivateKey, rootCertificate)
					if err != nil {
						return err
					}
					fmt.Println("ca cert and key generated")
				}

				key, cert, err := packager.GenerateEnd(c.String("common-name"), rootPrivateKey, rootCertificate)
				if err != nil {
					return err
				}
				err = packager.DumpKeyAndCertificateToFile(endKeyPath, endCertPath, key, cert)
				if err != nil {
					return err
				}
				fmt.Println("end cert and key generated")
				return nil
			},
		},

		{
			Name:  "pack",
			Usage: "打包",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "input",
					Usage:    "要打包的文件路径",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "output",
					Usage:    "打包后的文件路径",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "magic",
					Usage:    "文件 magic 头，用于区分文件类型和配置",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "end-cert",
					Usage: "end cert 路径",
					Value: "./end.crt",
				},
				&cli.StringFlag{
					Name:  "end-key",
					Usage: "end key 路径",
					Value: "./end.key",
				},
				&cli.StringSliceFlag{
					Name:  "extra-data",
					Usage: "额外想添加的数据，k=v 格式",
				},
				&cli.BoolFlag{
					Name:  "encrypt-extra-data",
					Usage: "是否加密额外数据",
				},
				&cli.StringFlag{
					Name:    "extra-data-aes-key",
					Usage:   fmt.Sprintf("加密额外数据的 aes key，必须是 %d 字节", packager.Aes256KeySize),
					EnvVars: []string{"EXTRA_DATA_AES_KEY"},
				},
				&cli.StringFlag{
					Name:     "main-data-aes-key",
					Usage:    fmt.Sprintf("加密主数据的 aes key, 必须是 %d 字节", packager.Aes256KeySize),
					Required: true,
					EnvVars:  []string{"MAIN_DATA_AES_KEY"},
				},
			},
			Action: func(c *cli.Context) error {
				input, err := os.Open(c.String("input"))
				if err != nil {
					return err
				}
				defer input.Close()
				stat, err := input.Stat()
				if err != nil {
					return err
				}

				key, cert, err := packager.LoadKeyAndCertificateFromFile(c.String("end-key"), c.String("end-cert"))
				if err != nil {
					return err
				}
				var magic [packager.MagicSize]byte
				if len([]byte(c.String("magic"))) > packager.MagicSize {
					return fmt.Errorf("magic too long")
				}
				copy(magic[:], c.String("magic"))

				extraData := make(map[string]string)
				for _, kv := range c.StringSlice("extra-data") {
					kvSlice := strings.SplitN(kv, "=", 2)
					if len(kvSlice) != 2 {
						return fmt.Errorf("invalid extra data format")
					}
					extraData[kvSlice[0]] = kvSlice[1]
				}
				var extraDataAesKey [packager.Aes256KeySize]byte
				encryptExtraData := c.Bool("encrypt-extra-data")
				if encryptExtraData {
					if len([]byte(c.String("extra-data-aes-key"))) != packager.Aes256KeySize {
						return errors.New("invalid extra data aes key size")
					}
					copy(extraDataAesKey[:], c.String("extra-data-aes-key"))
				}
				var mainDataAesKey [packager.Aes256KeySize]byte
				if len([]byte(c.String("main-data-aes-key"))) != packager.Aes256KeySize {
					return errors.New("invalid main data aes key size")
				}
				copy(mainDataAesKey[:], c.String("main-data-aes-key"))

				output, err := os.Create(c.String("output"))
				if err != nil {
					return err
				}
				defer output.Close()

				return packager.Pack(&packager.PackConfig{
					Magic:            magic,
					PrivateKey:       key,
					Certificate:      cert,
					ExtraData:        extraData,
					EncryptExtraData: encryptExtraData,
					ExtraDataAesKey:  extraDataAesKey,
					MainDataAesKey:   mainDataAesKey,
				}, input, uint64(stat.Size()), output)
			},
		},

		{
			Name:  "unpack",
			Usage: "解包",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "input",
					Usage:    "要解包的文件路径",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "output",
					Usage:    "解包后的文件路径",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "ca-cert",
					Usage: "ca cert 路径",
					Value: "./ca.crt",
				},
				&cli.StringFlag{
					Name:    "extra-data-aes-key",
					Usage:   fmt.Sprintf("加密额外数据的 aes key，必须是 %d 字节", packager.Aes256KeySize),
					EnvVars: []string{"EXTRA_DATA_AES_KEY"},
				},
				&cli.StringFlag{
					Name:     "main-data-aes-key",
					Usage:    fmt.Sprintf("加密主数据的 aes key, 必须是 %d 字节", packager.Aes256KeySize),
					Required: true,
					EnvVars:  []string{"MAIN_DATA_AES_KEY"},
				},
			},
			Action: func(c *cli.Context) error {
				input, err := os.Open(c.String("input"))
				if err != nil {
					return err
				}
				defer input.Close()

				var extraDataAesKey [packager.Aes256KeySize]byte
				cliExtraDataAesKey := []byte(c.String("extra-data-aes-key"))
				if len(cliExtraDataAesKey) != 0 && len(cliExtraDataAesKey) != packager.Aes256KeySize {
					return errors.New("invalid extra data aes key size")
				}
				copy(extraDataAesKey[:], c.String("extra-data-aes-key"))

				cliMainDataAesKey := []byte(c.String("main-data-aes-key"))
				if len(cliMainDataAesKey) != packager.Aes256KeySize {
					return errors.New("invalid main data aes key size")
				}
				var mainDataAesKey [packager.Aes256KeySize]byte
				copy(mainDataAesKey[:], c.String("main-data-aes-key"))

				caCertPath := c.String("ca-cert")
				caCertBytes, err := os.ReadFile(caCertPath)
				if err != nil {
					return err
				}
				caCert, err := x509.ParseCertificate(caCertBytes)
				if err != nil {
					return err
				}

				unpackConfig := &packager.UnpackConfig{
					CACertificate:   caCert,
					ExtraDataAesKey: extraDataAesKey,
					MainDataAesKey:  mainDataAesKey,
				}

				output, err := os.Create(c.String("output"))
				if err != nil {
					return err
				}
				defer output.Close()

				extraData, endCert, err := packager.Unpack(unpackConfig, input, output)
				if extraData != nil {
					data, _ := json.MarshalIndent(extraData, "", "  ")
					fmt.Printf("extra data:\n%s\n\n", string(data))
				}
				if endCert != nil {
					fmt.Printf("end cert:\n  subject: %s\n  serial: %s\n  validity bounds: %s - %s\n",
						endCert.Subject.String(), endCert.SerialNumber, endCert.NotBefore, endCert.NotAfter)
				}
				if err == nil {
					fmt.Println("unpack succeeded")
				}
				return err
			},
		},
		{
			Name:  "get-extra-data",
			Usage: "获取内嵌数据",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "input",
					Usage:    "要解包的文件路径",
					Required: true,
				},
				&cli.StringFlag{
					Name:     "output",
					Usage:    "将 extra-data 写入这个文件",
					Required: true,
				},
				&cli.StringFlag{
					Name:  "ca-cert",
					Usage: "ca cert 路径",
					Value: "./ca.crt",
				},
				&cli.StringFlag{
					Name:    "extra-data-aes-key",
					Usage:   fmt.Sprintf("加密额外数据的 aes key，必须是 %d 字节", packager.Aes256KeySize),
					EnvVars: []string{"EXTRA_DATA_AES_KEY"},
				},
				&cli.BoolFlag{
					Name:  "verify",
					Usage: "是否校验签名",
					Value: true,
				},
			},
			Action: func(c *cli.Context) error {
				caCertPath := c.String("ca-cert")
				caCertBytes, err := os.ReadFile(caCertPath)
				if err != nil {
					return err
				}
				caCert, err := x509.ParseCertificate(caCertBytes)
				if err != nil {
					return err
				}

				input, err := os.Open(c.String("input"))
				if err != nil {
					return err
				}

				var extraDataAesKey [packager.Aes256KeySize]byte
				cliExtraDataAesKey := []byte(c.String("extra-data-aes-key"))
				if len(cliExtraDataAesKey) != 0 && len(cliExtraDataAesKey) != packager.Aes256KeySize {
					return errors.New("invalid extra data aes key size")
				}
				copy(extraDataAesKey[:], cliExtraDataAesKey)

				extraData, cert, err := packager.GetExtraData(&packager.UnpackConfig{
					CACertificate:   caCert,
					ExtraDataAesKey: extraDataAesKey,
				}, input, c.Bool("verify"))
				if err != nil {
					return err
				}

				certData := map[string]string{
					"subject":    cert.Subject.String(),
					"serial":     cert.SerialNumber.String(),
					"not_before": fmt.Sprintf("%d", cert.NotBefore.Unix()),
					"not_after":  fmt.Sprintf("%d", cert.NotAfter.Unix()),
				}
				outputData, err := json.MarshalIndent(map[string]any{"extra_data": extraData, "cert": certData}, "", "    ")
				if err != nil {
					return err
				}
				fmt.Println(string(outputData))
				err = os.WriteFile(c.String("output"), outputData, 0644)
				return err
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("run app failed, err: %v\n", err)
		os.Exit(1)
	}
}
