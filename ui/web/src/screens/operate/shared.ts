// errorMessage now lives in the shared src/errorMessage.ts module; it is
// re-exported here so the operate/* screens can keep importing it locally.
export { errorMessage } from "../../errorMessage";
