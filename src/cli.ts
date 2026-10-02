#!/usr/bin/env node
import { main } from "./run.ts";

main().then((code) => { process.exitCode = code; });
