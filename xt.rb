#https://bitaps.com/broadcast - отправить транзакцию в сеть
#https://habr.com/ru/post/319862/ - Bitcoin in a nutshell — Protocol
#https://bitcoin-script-debugger.visvirial.com/ - дебугер скриптов биткоин
#https://bitcoin.stackexchange.com/questions/32628/redeeming-a-raw-transaction-step-by-step-example-required - алгоритм формирования транзакции
#https://medium.com/swlh/create-raw-bitcoin-transaction-and-sign-it-with-golang-96b5e10c30aa
#https://blockstream.info/address/1nT8wyJjV7LBhuv993qoQ2R2k6HvpPFwg
#https://habr.com/ru/post/319868/
#https://en.bitcoin.it/wiki/OP_CHECKSIG#How_it_works
require './keys.rb'

class Tx
  N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
  def build_P2PKH opts
    keys = opts[:keys]
    # Формируем транзакцию
    version = '01000000' #версия 1
    sequence = 'ffffffff' #just some constant
    lock_time = '00000000' #количество времени для блокировки транзакции
    hash_code_type = '01000000' #тип подписи - подписываем все входы и выходы
    outputs_count = '01' #количество выходов

    #количество входов в транзакции
    inputs_count = byte_length(opts[:inputs_cnt].to_s(16), 1)

    #id транзакции которая поступает на вход:
    prev_tx_hash = little_endian(opts[:hash_prev_tx])

    prev_out_index = byte_length(opts[:output_id].to_s(16), 4)#'01000000'номер выхода, который передаем на вход
    prev_out_index = little_endian(prev_out_index)
    amount = byte_length opts[:amount].to_s(16), 8
    amount = little_endian amount #количество сатошей для перевода (hex)
    #блокирующая часть смарт контракта P2PKH (Pay-to-Public-Key Hash):
    # Механизм проверки действительности транзакций, а заодно, и вся система передачи
    # ценности от одного владельца другому в блокчейне платформы Биткоин опирается на
    # два типа сценариев: блокирующий сценарий и разблокирующий.
    # Блокирующий скрипт воплощает налагаемое на выход транзакции обременение.
    # Здесь определяются условия, выполнение которых откроет в будущем доступ к средствам,
    # замороженным на выходе транзакции. Исторически сложилось так, что сценарий
    # блокировки назывался scriptPubKey (сценарий открытого ключа).
    # В большинстве случаев этот скрипт действительно хранил открытый ключ или биткоин-адрес.
    #OP_DUP OP_HASH160 DESTINATION_ADDR OP_EQUALVERIFY OP_CHECKSIG
    # OP_DUP: Duplicates the top stack item. (0x76)
    # OP_HASH160: The input is hashed twice: first with SHA-256 and then with RIPEMD-160. (0xa9)
    # OP_EQUALVERIFY: Same as OP_EQUAL, but runs OP_VERIFY afterward. (0x88)
    # OP_CHECKSIG: The entire transaction's outputs, inputs, and script
    #(from the most recently-executed OP_CODESEPARATOR to the end) are hashed.
    #The signature used by OP_CHECKSIG must be a valid signature for this hash
    #and public key. If it is, 1 is returned, 0 otherwise. (ac)
    # здесь 0x14: OP_PUSHBYTES[20] поместить в буфер 160 бит (20 байт)
    script_sig_len = '19'
    script_sig = '76a914'+opts[:dest_address_hash]+'88ac'
    script_pub_key_len = '19' #длина разблокирующего скрипта
    script_pub_key = '76a914'+opts[:dest_address_hash]+'88ac'

    #Составляем предварительную транзакцию для подписи
    tx = ''
    tx << version << ' ' << inputs_count << "\n" << prev_tx_hash << "\n" 
    tx << prev_out_index << "\n" << script_sig_len << ' ' << script_sig << "\n" 
    tx << sequence << "\n" << outputs_count << "\n" << amount << "\n" << script_pub_key_len << ' ' 
    tx << script_pub_key << "\n" << lock_time << "\n" << hash_code_type
    tx.gsub!("\n", '').gsub!(' ', '')

    # puts [tx].pack('H*')
    # puts [tx].pack('H') 
    #От получившейся транзакции берем двойной хеш SHA256
    tx_hash = Digest::SHA256.hexdigest [tx].pack('H*')
    tx_hash = Digest::SHA256.hexdigest [tx_hash].pack('H*')
    puts "tx_hash: #{tx_hash}"
    tx_hash = tx_hash.unpack('H*')[0]
    #Подписываем получившийся двойной хеш и представляем в формате DER -
    #это и будет подпись для подтверждения владения входом транзакции,
    #после чего к подписи добавляем 01 в конец
    group = ECDSA::Group::Secp256k1
    signature = nil
    while signature.nil?
      temp_key = 1 + SecureRandom.random_number(group.order - 1)
      signature = ECDSA.sign(group, keys.priv(hex: true).to_i(16), tx_hash, temp_key)
    end

    # Чтобы избежать ошибки: Non-canonical signature: S value is unnecessarily high
    if N/2 < signature.s
            puts "warning s > N/2"
            signature = ECDSA::Signature.new(signature.r, N - signature.s)
    end

    signature_der = ECDSA::Format::SignatureDerString.encode(signature).unpack('H*')[0]
    signature_der_string = signature_der + '01'
    puts "sig DER: #{signature_der_string}"

    #Проверка подписи на валидность.
    # Берем исходное подписанное сообщение, публичный ключ и саму подпись и выясняем,
    # было ли это сообщение подписано полученной подписью с помощью закрытого ключа,
    # которому в соответствие поставлен данный открытый ключ
    valid = ECDSA.valid_signature?(keys.pub(as_point: true), tx_hash, signature)
    puts "signature valid: #{valid}"

    # Каждый из скриптов выполняется отдельно, по очереди, а полученный
    # после выполнения первого скрипта результат передается через стек.
    # Рассмотрим подробнее каким образом это реализуется.

    # Сначала выполняется разблокирующий скрипт. Если он выполнился без ошибок
    # (например, не осталось лишних операторов), основной (не альтернативный) стек копируется.
    # Затем запускается на исполнение блокирующий скрипт. Если результат выполнения блокирующего
    # скрипта с ранее скопированным из стека результатом разблокирующего скрипта дает
    # значение "TRUE", то данный вход транзакции признается действительным
    # (в случае получения такого же результата проверок для остальных входов,
    # транзакция считается полностью готовой (валидной) к включению в блокчейн).
    # Т.е., разблокирующий скрипт смог полностью удовлетворить условиям обременения,
    # закодированным в блокирующем скрипте и, следовательно, данный вход успешно
    # подтвердил полномочия на трату конкретного неизрасходованного выхода. Если же в
    # результате выполнения объединенного сценария получен иной результат (не "TRUE"),
    # тогда вход признается недействительным, как не удовлетворившим условия доступа к
    # средствам, закодированные в соответствующем нерастраченном выходе. Поскольку
    # нерастраченный выход вместе с остальными частями транзакции уже записан в блокчейн
    # (т.е., никогда не меняется), никакие недействительные (неудачные, или злонамеренные)
    # попытки израсходовать его по ссылке из новой транзакции никак не могут на него повлиять.
    # Только действительная транзакция, удовлетворяющая условиям ограничения, изменит состояние
    # нерастраченного выхода на "растраченный" и вызовет его удаление из пула доступных
    # (нерастраченных) выходов.
    # Составляем разблокирующую часть смарт контракта:
    len = byte_length((signature_der_string.length/2).to_s(16), 1)
    pub = keys.pub(compressed: false)
    script_sig = len
    script_sig << signature_der_string
    script_sig << byte_length((pub.length/2).to_s(16), 1)
    script_sig << pub
    script_sig_len = (script_sig.length/2).to_s(16)

    #Получаем подписанную готовую транзакцию
    tx = ''
    tx << version << inputs_count << prev_tx_hash
    tx << prev_out_index << script_sig_len << script_sig
    tx << sequence << outputs_count << amount << script_pub_key_len
    tx << script_pub_key << lock_time

    puts "signed tx: #{tx}"

    tx
  end
private
  def little_endian(str)
          (0..(str.length-1)/2).map{|i|str[i*2,2]}.reverse.join
  end

  def byte_length x, len
    res = ''
    for i in 1..len*2-x.length do
      res << '0'
    end
    res << x
  end
end


keys = Keys.new
keys.generate 'priv key'
dest_keys = Keys.new
dest_keys.generate 'priv key'

tx = Tx.new
tx.build_P2PKH({
    :hash_prev_tx => '5b8be25912bb21bfe335b320a2c3144aa97c8f4d5961f125cd6f6070ffa711f8',
    :output_id => 0,
    :inputs_cnt => 1,
    :keys => keys,
    :dest_address_hash => dest_keys.address(hash160: true),
    :amount => 127800}) #в сатоши

#real transaction
# 0100000001f811a7ff70606fcd25f161594d8f7ca94a14c3a220b335e3bf21bb1259e28b5b000000008b483045022100c5df0367b35c5681780eab1fb011f50a1901eeb8466f579e30e58281867db67502202d4b96d83be828dcb8c3ee309532ed73c97d42ddf8b986028b3992ee8c2dbc9f0141042f7cad7901354735df7f024a9a0d7a3e3454ede6afa1d9c7b31125392a5fb7c9b29362514c32cd9bef62840b5a3b430dfafa1338268dd4629cbea75eefa0be90ffffffff0138f30100000000001976a914558bf351cf5207dbd7bd0f13f095f686b1291b0588ac00000000

puts "КЛЮЧИ ОТ АДРЕСА С КОТОРОГО СПИСЫВАЕМ"
puts "ПРИВАТНЫЙ КЛЮЧ"
puts "  Шестнадцатеричная запись:     #{keys.priv hex: true}"
puts "ОТКРЫТЫЙ КЛЮЧ"
puts "  Несжатая запись:              #{keys.pub(compressed: false).downcase}"
puts "  Сжатая запись:                #{keys.pub(compressed: true).downcase}"
puts "АДРЕС:"
puts "  Сжатая запись:                #{keys.address b58: true}"
puts "  HASH160:                      #{keys.address(hash160: true)}"
puts "================================================================"
puts "КЛЮЧИ ОТ АДРЕСА НА КОТОРЫЙ ПЕРЕСЫЛАЕМ"
puts "АДРЕС:"
puts "  Сжатая запись:                #{dest_keys.address b58: true}"
puts "  HASH160:                      #{dest_keys.address(hash160: true)}"