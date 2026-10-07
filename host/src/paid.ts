/**
 * The host's terms route (spec section 10.3): bcommon's shared route
 * (`@lightwebinc/bcommon/host`, LookupFront) with bsecret's names, classes and
 * payment protocol, beside the overlay host, whose base URL is what
 * BRC-180's `metanet.overlays` names for `ls_bsecret`. It serves
 *
 *   GET  <base>/ls_bsecret/terms     the host terms document (404 when the host prices nothing)
 *   POST <base>/.well-known/auth  the BRC-104 handshake
 *   POST <base>/lookup            BRC-24 questions to ls_bsecret, free and priced
 *
 * Metric names (`bsecret_*`), log lines, status codes, bodies and ledger lines
 * are the ones this file wrote when it carried the route itself.
 * A session's response budget is taken after the request's signature is
 * verified. A ledger line puts the host's decision before `at` (`spread`).
 *
 * The overlay host's own /lookup refuses a class the host prices (ls_bsecret
 * does), so this route is the only way to it.
 */
import { parsePrices as sharedPrices, termsDocument as sharedTerms, termsPath, type FrontOptions, type LedgerOptions, type LookupAnswerer } from '@lightwebinc/bcommon/host'
import { LookupService as ServiceName } from './secrec.js'
import type { SecretLookupService } from './ls_bsecret.js'
import { Classes } from './query.js'

/** BRC-29's derivation protocol, under which a priced question's payment pays the host (spec section 10.3). */
export const PaymentProtocol: [2, string] = [2, '3241645161d8']

/** The terms route, below the base URL. */
export const TermsPath = termsPath(ServiceName)

/**
 * Parses a host's prices, `history=5,history-after=5`: a comma list of
 * `<class>=<satoshis>`, each a priceable class of spec section 10.2 once,
 * priced 0 to 2^53 - 1. A free class is refused: it never has a price. A
 * class and its `-after` form are priced together or not at all.
 */
export function parsePrices(raw: string | undefined): Map<string, number> {
  return sharedPrices(raw, Classes, 'BSECRET_PRICES')
}

/** The host terms document (spec section 10.3), classes in the order of section 10.2. */
export function termsDocument(prices: ReadonlyMap<string, number>): { service: string; terms: number; classes: Array<{ class: string; satoshis: number }> } {
  return sharedTerms(ServiceName, Classes, prices)
}

/** ls_bsecret as the shared route asks its questions: a priced answer is hydrated as the engine hydrates one. */
export function answerer(ls: SecretLookupService): LookupAnswerer {
  return {
    get restored() {
      return ls.restored
    },
    classify: (q) => ls.classify(q).q.class.name,
    answer: async (q) => ls.hydrate(await ls.answer(q, true)),
  }
}

/** What the shared route takes of bsecret: its names, its classes, its payment protocol and ls_bsecret. */
export function bsecretRoute(ls: SecretLookupService): Pick<FrontOptions, 'app' | 'service' | 'classes' | 'paymentProtocol' | 'ls' | 'responseBudget'> {
  return { app: 'bsecret', service: ServiceName, classes: Classes, paymentProtocol: PaymentProtocol, ls: answerer(ls), responseBudget: 'after-verify' }
}

/** The ledger's layout: the decision before `at`, as bsecret has always written it. */
export const Ledger: LedgerOptions = { layout: 'spread' }
