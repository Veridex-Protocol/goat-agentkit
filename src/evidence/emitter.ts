import { EventEmitter } from "events";
import { EvidenceBundle } from "./builder.js";

export class EvidenceEmitter extends EventEmitter {
  public emitBundle(bundle: EvidenceBundle): void {
    this.emit("bundle", bundle);
  }

  public onBundle(listener: (bundle: EvidenceBundle) => void): this {
    return this.on("bundle", listener);
  }
}
