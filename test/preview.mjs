import {createPanel} from '../server.mjs';
import {fakeRouter,testConfig} from './fixture.mjs';
const {origin}=await createPanel({config:testConfig,router:fakeRouter(),port:18651,demo:true});
console.log(origin);
