require 'bitcoin'
# use testnet so you don't accidentally blow your whole money!
Bitcoin.network = :bitcoin

# make the DSL methods available in your scope
include Bitcoin::Builder

# the previous transaction that has an output to your address

prev_hash = "5b8be25912bb21bfe335b320a2c3144aa97c8f4d5961f125cd6f6070ffa711f8"

# the number of the output you want to use
prev_out_index = 0

# fetch the tx from whereever you like and parse it

prev_tx = Bitcoin::P::Tx.new ['01000000000101be74d8f6ba077841f9d7cdee692f1e17ae10e7f41415768f2a4e22d983b68f7601000000232200202a7c65c508f9279b3ce1762b110cf8e7d82554b773012e131e96b8f7b9dfc737ffffffff023ff30100000000001976a9140898894fdd1b1bfde9bfa4a73f24c1ff995b023288ac1ffb8d010000000017a91456d6d63d0196c0a2fe57b728b8a8b58095d6b02c870400473044022054a12288ec14584700bc1ef292cfcfef58942b711d455d3177c9fe086fa8837902206575bd090852dd2fc52da2e2d3d0e1c7ad767ee6426147866b8e4f101369cc0501473044022013852bd7a50977d3eae2d73a463d201ac54e8504633e36f40169a6898de4efdf02206b4c4867df653299d7031d0b92962efbb02c9daa7ef18b66a3c3466ecb44cdcd01475221027d8349aa355b81bcd948e0dd1df3cd01498bd194d2d1e901b74a5e7e7c520eb121032b8ebcde5b201bf6ac9684641c5087ed1cc8a9f516ee939609caf0b5d4de460952ae00000000'].pack("H*")
# the key needed to sign an input that spends the previous output
key = Bitcoin::Key.new('puts here private key')

# create a new transaction (and sign the inputs)
new_tx = build_tx do |t|

  # add the input you picked out earlier
  t.input do |i|
    i.prev_out prev_tx
    i.prev_out_index prev_out_index
    i.signature_key key
  end

  # add an output that sends some bitcoins to another address
  t.output do |o|
    o.value 127807 # 0.5 BTC in satoshis
    o.script {|s| s.recipient "18oL6EbtdWFnES9KfNvgBqVBjPyBbP4Qok" }
  end

  # add another output spending the remaining amount back to yourself
  # if you want to pay a tx fee, reduce the value of this output accordingly
  # if you want to keep your financial history private, use a different address
  # t.output do |o|
  #   o.value 49000000 # 0.49 BTC, leave 0.01 BTC as fee
  #   o.script {|s| s.recipient key.addr }
  # end

end

# examine your transaction. you can relay it through http://test.webbtc.com/relay_tx
# that will also give you a hint on the error if something goes wrong
puts new_tx.to_payload.bth