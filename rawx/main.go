// OpenIO SDS Go rawx
// Copyright (C) 2015-2019 OpenIO SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

/*
Parses and checks the CLI arguments, then ties together a repository and a
http handler.
*/

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

func checkURL(url string) {
	addr, err := net.ResolveTCPAddr("tcp", url)
	if err != nil || addr.Port <= 0 {
		log.Fatalf("%s is not a valid URL", url)
	}
}

// TODO(jfs): the pattern doesn't patch the requirement
func checkNS(ns string) {
	if ok, _ := regexp.MatchString("[0-9a-zA-Z]+(\\.[0-9a-zA-Z]+)*", ns); !ok {
		log.Fatalf("%s is not a valid namespace name", ns)
	}
}

func usage(why string) {
	log.Println("rawx NS IP:PORT BASEDIR")
	log.Fatal(why)
}

func installSigHandlers(rawx *rawxService, srv *http.Server) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		syscall.SIGINT,
		syscall.SIGTERM)

	go func() {
		for {
			switch <-signalChan {
			case syscall.SIGUSR1:
				increaseVerbosity()
				go func() {
					time.Sleep(time.Minute * 15)
					resetVerbosity()
				}()
			case syscall.SIGUSR2:
				resetVerbosity()
			case syscall.SIGINT, syscall.SIGTERM:
				ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
				if err := srv.Shutdown(ctx); err != nil {
					LogWarning("graceful shutdown error: %v", err)
				}
			}
		}
	}()
}

func main() {
	_ = flag.String("D", "UNUSED", "Unused compatibility flag")
	verbosePtr := flag.Bool("v", false, "Verbose mode, this activates stderr traces")
	syslogIDPtr := flag.String("s", "", "Activates syslog traces with the given identifier")
	confPtr := flag.String("f", "", "Path to configuration file")
	servicingPtr := flag.Bool("servicing", false, "Don't lock volume")
	flag.Parse()

	if flag.NArg() != 0 {
		log.Fatal("Unexpected positional argument detected")
	}

	if *verbosePtr {
		InitStderrLogger()
	} else if *syslogIDPtr != "" {
		InitSysLogger(*syslogIDPtr)
	} else {
		InitNoopLogger()
	}

	var opts optionsMap

	if len(*confPtr) <= 0 {
		log.Fatal("Missing configuration file")
	} else if cfg, err := filepath.Abs(*confPtr); err != nil {
		log.Fatal("Invalid configuration file path", err.Error())
	} else if opts, err = readConfig(cfg); err != nil {
		log.Fatal("Exiting with error: ", err.Error())
	}

	chunkrepo := chunkRepository{}
	namespace := opts["ns"]
	rawxURL := opts["addr"]
	rawxID := opts["id"]

	checkNS(namespace)
	checkURL(rawxURL)

	// No service ID specified, using the service address instead
	if rawxID == "" {
		rawxID = rawxURL
		LogInfo("No service ID, using ADDR %s", rawxURL)
	}

	// Init the actual chunk storage
	if err := chunkrepo.sub.init(opts["basedir"]); err != nil {
		log.Fatal("Invalid directories: ", err)
	}
	chunkrepo.sub.hashWidth = opts.getInt("hash_width", chunkrepo.sub.hashWidth)
	chunkrepo.sub.hashDepth = opts.getInt("hash_depth", chunkrepo.sub.hashDepth)
	chunkrepo.sub.syncFile = opts.getBool("fsync_file", chunkrepo.sub.syncFile)
	chunkrepo.sub.syncDir = opts.getBool("fsync_dir", chunkrepo.sub.syncDir)
	chunkrepo.sub.fallocateFile = opts.getBool("fallocate", chunkrepo.sub.fallocateFile)

	rawx := rawxService{
		ns:       namespace,
		url:      rawxURL,
		path:     chunkrepo.sub.root,
		id:       rawxID,
		repo:     &chunkrepo,
		compress: opts.getBool("compress", false),
	}

	eventAgent := OioGetEventAgent(namespace)
	if eventAgent == "" {
		log.Fatal("Notifier error: no address")
	}

	notifier, err := MakeNotifier(eventAgent, &rawx)
	if err != nil {
		log.Fatal("Notifier error: ", err)
	}
	rawx.notifier = notifier

	srv := http.Server{
		Addr:              rawx.url,
		Handler:           &rawx,
		TLSConfig:         nil,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       20 * time.Second,
		// The default is at 1MiB but the RAWX never needs that
		MaxHeaderBytes: 65536,
	}

	installSigHandlers(&rawx, &srv)

	rawx.notifier.Start()

	if !*servicingPtr {
		if err := chunkrepo.lock(namespace, rawxID); err != nil {
			log.Fatal("Volume lock error: ", err.Error())
		}
	}

	// TODO(jfs): make this configurable
	srv.SetKeepAlivesEnabled(true)

	if *verbosePtr {
		srv.ConnState = func(cnx net.Conn, state http.ConnState) {
			LogDebug("cnx %v state %v", cnx, state)
		}
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Println("HTTP Server error: ", err)
	}

	rawx.notifier.Stop()
}
