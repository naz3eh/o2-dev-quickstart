import {
  Address,
  arrayify,
  B256Coder,
  BigNumberCoder,
  bn,
  BN,
  concat,
  Contract,
  EnumCoder,
  hexlify,
  OptionCoder,
  Provider,
  sha256,
  Signer,
  StructCoder,
  TupleCoder,
  VecCoder,
  toUtf8Bytes,
} from 'fuels';

// Configuration 

const REST_URL = 'https://api.testnet.o2.app';
const PROVIDER_URL = 'https://testnet.fuel.network/v1/graphql';
const OWNER_PRIVATE_KEY = '0x122746c21196c4064426ff3a100b1c7c00a687711ed9fc287bcba5511491c359';

// Minimal ABI/coders to avoid generated contract types in this example.
const TRADE_ACCOUNT_ABI = {
  programType: 'contract',
  specVersion: '1.1',
  encodingVersion: '1',
  concreteTypes: [
    {
      type: 'u64',
      concreteTypeId: 'u64',
    },
  ],
  metadataTypes: [],
  functions: [
    {
      name: 'get_nonce',
      inputs: [],
      output: 'u64',
      attributes: null,
    },
  ],
  loggedTypes: [],
  messagesTypes: [],
  configurables: [],
};

// Types 

enum OrderType {
  Spot = 'Spot',
  Market = 'Market',
}

enum OrderSide {
  Buy = 'Buy',
  Sell = 'Sell',
}

// Helper Functions 

function getAddress(bits: string | Address) {
  return { Address: { bits: bits.toString() } };
}

function getOption(args?: Uint8Array) {
  if (args) {
    return concat([new BigNumberCoder('u64').encode(1), args]);
  }
  return new BigNumberCoder('u64').encode(0);
}

function createSession(
  address: Address,
  contract_ids: string[],
  expiry: number = Date.now() + 320 * 60 * 1000
) {
  return {
    session_id: getAddress(address),
    expiry: { unix: bn(expiry.toString()) },
    contract_ids: contract_ids.map((id) => ({ bits: id })),
  };
}

function createCallToSign(
  nonce: number,
  chainId: number,
  funcName: string,
  argBytes: Uint8Array
): Uint8Array {
  const funcNameBytes = toUtf8Bytes(funcName);
  return concat([
    new BigNumberCoder('u64').encode(nonce),
    new BigNumberCoder('u64').encode(chainId),
    new BigNumberCoder('u64').encode(funcNameBytes.length),
    funcNameBytes,
    argBytes,
  ]);
}

// Personal sign format: prefix + length + message, then sha256
const FUEL_MESSAGE_PREFIX = '\x19Fuel Signed Message:\n';

function hashPersonalMessage(message: Uint8Array): string {
  const payload = concat([
    toUtf8Bytes(FUEL_MESSAGE_PREFIX),
    toUtf8Bytes(String(message.length)),
    message,
  ]);
  return sha256(payload);
}

// Encode call contract to bytes for session signing
function callContractToBytes(params: {
  contractId: string;
  functionSelector: string;
  amount: BN;
  assetId: string;
  gas: BN;
  args?: Uint8Array;
}): Uint8Array {
  const selectorBytes = arrayify(params.functionSelector);
  return concat([
    params.contractId,
    new BigNumberCoder('u64').encode(selectorBytes.length),
    selectorBytes,
    new BigNumberCoder('u64').encode(params.amount),
    arrayify(params.assetId),
    new BigNumberCoder('u64').encode(params.gas),
    getOption(
      params.args
        ? concat([new BigNumberCoder('u64').encode(params.args.length), params.args])
        : undefined
    ),
  ]);
}

// Session signer: sha256(data) then sign
function sessionSign(signer: Signer, data: Uint8Array): string {
  const hash = sha256(data);
  return signer.sign(hash);
}

// Calculate amount based on side
function calculateAmount(
  side: OrderSide,
  price: bigint,
  quantity: bigint,
  baseDecimals: number
): BN {
  if (side === OrderSide.Buy) {
    return bn(((price * quantity) / BigInt(10 ** baseDecimals)).toString());
  }
  return bn(quantity.toString());
}

// Encoders https://docs.fuel.network/docs/fuels-ts/encoding/working-with-bytes/
const U64_CODER = new BigNumberCoder('u64');
const B256_CODER = new B256Coder();

const ADDRESS_CODER = new StructCoder('Address', { bits: B256_CODER });
const CONTRACT_ID_CODER = new StructCoder('ContractId', { bits: B256_CODER });
const IDENTITY_CODER = new EnumCoder('Identity', {
  Address: ADDRESS_CODER,
  ContractId: CONTRACT_ID_CODER,
});
const TIME_CODER = new StructCoder('Time', { unix: U64_CODER });
const CONTRACT_IDS_CODER = new VecCoder(CONTRACT_ID_CODER);
const SESSION_CODER = new StructCoder('Session', {
  session_id: IDENTITY_CODER,
  expiry: TIME_CODER,
  contract_ids: CONTRACT_IDS_CODER,
});
const SESSION_OPTION_CODER = new OptionCoder('Option<Session>', {
  None: new TupleCoder([]),
  Some: SESSION_CODER,
});

const ORDER_TYPE_CODER = new EnumCoder('OrderType', {
  Limit: new TupleCoder([U64_CODER, TIME_CODER]),
  Spot: new TupleCoder([]),
  FillOrKill: new TupleCoder([]),
  PostOnly: new TupleCoder([]),
  Market: new TupleCoder([]),
  BoundedMarket: new TupleCoder([U64_CODER, U64_CODER]),
});
const ORDER_ARGS_CODER = new StructCoder('OrderArgs', {
  price: U64_CODER,
  quantity: U64_CODER,
  order_type: ORDER_TYPE_CODER,
});

function encodeFunctionSelector(name: string): Uint8Array {
  const nameBytes = toUtf8Bytes(name);
  return concat([U64_CODER.encode(name.length), nameBytes]);
}

// Main 

async function main() {
  // 1. Setup provider and owner
  const provider = new Provider(PROVIDER_URL);
  const ownerSigner = new Signer(OWNER_PRIVATE_KEY);
  const ownerAddress = ownerSigner.address.toB256();
  const chainId = await provider.getChainId();

  console.log('Owner Address:', ownerAddress);
  console.log('Chain ID:', chainId);

  // 2. Generate random session signer
  const sessionPrivateKey = Signer.generatePrivateKey();
  const sessionSigner = new Signer(sessionPrivateKey);
  console.log('Session Private Key:', hexlify(sessionPrivateKey));
  console.log('Session Address:', sessionSigner.address.toB256());

  // 3. Create/fetch trading account
  const accountRes = (await fetch(new URL('./v1/accounts', REST_URL), {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      identity: { Address: ownerAddress },
    }),
  }).then((r) => r.json())) as { trade_account_id?: string; nonce?: string };

  if (!accountRes.trade_account_id) {
    throw new Error('Trading account not found');
  }

  const tradeAccountId = accountRes.trade_account_id;
  console.log('Trade Account ID:', tradeAccountId);

  // 4. Fetch nonce from the contract
  const tradeAccount = new Contract(tradeAccountId, TRADE_ACCOUNT_ABI, provider);
  const { value: nonce } = await tradeAccount.functions.get_nonce().get();
  console.log('Nonce:', nonce.toString());

  // 5. Fetch markets to get contract IDs and market info
  interface Market {
    market_id: string;
    contract_id: string;
    base: { asset: string; decimals: number };
    quote: { asset: string; decimals: number };
  }
  const marketsRes = (await fetch(new URL('./v1/markets', REST_URL)).then((r) =>
    r.json()
  )) as { markets: Market[] };
  const contractIds = marketsRes.markets.map((m) => m.contract_id);
  const market = marketsRes.markets[0]; // Use first market
  console.log('Contract IDs:', contractIds);
  console.log('Using market:', market.market_id);

  // 6. Create session input and bytes to sign
  const session = createSession(sessionSigner.address, contractIds);
  const sessionArgBytes = SESSION_OPTION_CODER.encode(session);
  const bytesToSign = createCallToSign(nonce.toNumber(), chainId, 'set_session', sessionArgBytes);

  // 7. Sign with owner (personal sign format)
  const messageHash = hashPersonalMessage(bytesToSign);
  const signature = ownerSigner.sign(messageHash);

  // 8. Build session API params
  const sessionParams = {
    nonce: nonce.toString(),
    contract_id: tradeAccountId,
    session_id: { Address: sessionSigner.address.toB256() },
    contract_ids: contractIds,
    signature: { Secp256k1: signature },
    expiry: session.expiry.unix.toString(),
  };

  console.log('Session Params:', JSON.stringify(sessionParams, null, 2));

  // 9. Create session via API
  const sessionRes = await fetch(new URL('./v1/session', REST_URL), {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'o2-owner-id': ownerAddress,
      'x-rate-limit-id': ownerAddress,
    },
    body: JSON.stringify(sessionParams),
  }).then((r) => r.json());

  console.log('Session Response:', sessionRes);

  // CREATE ORDER 
  console.log('\nCreating Order');

  // Use incremented nonce (session creation used one nonce)
  const orderNonce = nonce.add(1);
  console.log('Order Nonce:', orderNonce.toString());

  // 11. Order parameters
  const orderSide = OrderSide.Buy;
  const orderType = OrderType.Spot;
  const price = BigInt(1000000000000); // 1000.0 in 9 decimals
  const quantity = BigInt(100000000); // 0.1 in 9 decimals

  // 12. Create order args
  const baseDecimals = market.base.decimals;

  const orderTypeValue = orderType === OrderType.Spot ? { Spot: [] } : { Market: [] };
  const orderArgs = {
    price: bn(price.toString()),
    quantity: bn(quantity.toString()),
    order_type: orderTypeValue,
  };

  const forwardAmount = calculateAmount(orderSide, price, quantity, baseDecimals);
  const forwardAssetId = orderSide === OrderSide.Buy ? market.quote.asset : market.base.asset;

  // 13. Prepare call params
  const forward = { assetId: forwardAssetId, amount: forwardAmount };
  const GAS_LIMIT_DEFAULT = bn('18446744073709551615');

  // 14. Encode call to bytes
  const orderContractId = market.contract_id;
  const orderSelectorBytes = encodeFunctionSelector('create_order');
  const orderArgBytes = ORDER_ARGS_CODER.encode(orderArgs);

  const callBytes = callContractToBytes({
    contractId: orderContractId,
    functionSelector: hexlify(orderSelectorBytes),
    amount: bn(forward.amount),
    assetId: forward.assetId,
    gas: GAS_LIMIT_DEFAULT,
    args: orderArgBytes,
  });

  // 15. Sign with session signer: nonce + length + bytes
  // Length is the number of calls (1 in this case)
  const numCalls = 1;
  const sessionBytesToSign = concat([
    new BigNumberCoder('u64').encode(orderNonce),
    new BigNumberCoder('u64').encode(numCalls),
    callBytes,
  ]);
  const sessionSignature = sessionSign(sessionSigner, sessionBytesToSign);

  // 16. Build session actions payload
  const actionsPayload = {
    actions: [
      {
        market_id: market.market_id,
        actions: [
          {
            CreateOrder: {
              side: orderSide,
              order_type: orderType,
              price: price.toString(),
              quantity: quantity.toString(),
            },
          },
        ],
      },
    ],
    signature: { Secp256k1: sessionSignature },
    nonce: orderNonce.toString(),
    trade_account_id: tradeAccountId,
    session_id: { Address: sessionSigner.address.toB256() },
    variable_outputs: 0,
    collect_orders: false,
  };

  console.log('Actions Payload:', JSON.stringify(actionsPayload, null, 2));

  // 17. Submit order via session actions API
  const orderRes = await fetch(new URL('./v1/session/actions', REST_URL), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'o2-owner-id': ownerAddress,
      'x-rate-limit-id': ownerAddress,
    },
    body: JSON.stringify(actionsPayload),
  }).then((r) => r.json());

  console.log('Order Response:', orderRes);
}

main().catch(console.error);
