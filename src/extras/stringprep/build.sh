#!/bin/bash

ghc -o Setup Setup.hs
./Setup configure
./Setup build
sudo ./Setup install
ghc -o runStringPrep runStringPrep.hs