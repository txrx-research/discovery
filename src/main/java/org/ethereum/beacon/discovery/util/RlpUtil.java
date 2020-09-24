/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.util;

import static org.web3j.rlp.RlpDecoder.OFFSET_LONG_LIST;
import static org.web3j.rlp.RlpDecoder.OFFSET_SHORT_LIST;

import java.math.BigInteger;
import java.util.function.Function;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.web3j.rlp.RlpDecoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;

/**
 * Handy utilities used for RLP encoding and decoding and not fulfilled by {@link
 * org.web3j.rlp.RlpEncoder} and {@link RlpDecoder}
 */
public class RlpUtil {
  /**
   * Calculates length of list beginning from the start of the data. So, there could everything else
   * after first list in data, method helps to cut data in this case.
   */
  public static int calcListLen(Bytes data) {
    int prefix = data.get(0) & 0xFF;
    int prefixAddon = 1;
    if (prefix >= OFFSET_SHORT_LIST && prefix <= OFFSET_LONG_LIST) {

      // 4. the data is a list if the range of the
      // first byte is [0xc0, 0xf7], and the concatenation of
      // the RLP encodings of all items of the list which the
      // total payload is equal to the first byte minus 0xc0 follows the first byte;

      byte listLen = (byte) (prefix - OFFSET_SHORT_LIST);
      return listLen & 0xFF + prefixAddon;
    } else if (prefix > OFFSET_LONG_LIST) {

      // 5. the data is a list if the range of the
      // first byte is [0xf8, 0xff], and the total payload of the
      // list which length is equal to the
      // first byte minus 0xf7 follows the first byte,
      // and the concatenation of the RLP encodings of all items of
      // the list follows the total payload of the list;

      int lenOfListLen = (prefix - OFFSET_LONG_LIST) & 0xFF;
      prefixAddon += lenOfListLen;
      return UInt64.fromBytes(Utils.leftPad(data.slice(1, lenOfListLen & 0xFF), 8)).intValue()
          + prefixAddon;
    } else {
      throw new RuntimeException("Not a start of RLP list!!");
    }
  }

  /**
   * @return first rlp list in provided data, plus remaining data starting from the end of this list
   */
  public static DecodedList decodeFirstList(Bytes data) {
    int len = RlpUtil.calcListLen(data);
    return new DecodedList(RlpDecoder.decode(data.slice(0, len).toArray()), data.slice(len));
  }

  /**
   * Encodes object to {@link RlpString}. Supports numbers, {@link Bytes} etc.
   *
   * @throws RuntimeException with errorMessageFunction applied with `object` when encoding is not
   *     possible
   */
  public static RlpString encode(Object object, Function<Object, String> errorMessageFunction) {
    if (object instanceof Bytes) {
      return fromBytesValue((Bytes) object);
    } else if (object instanceof Number) {
      return fromNumber((Number) object);
    } else if (object == null) {
      return RlpString.create(new byte[0]);
    } else if (object instanceof IdentitySchema) {
      return RlpString.create(((IdentitySchema) object).stringName());
    } else {
      throw new RuntimeException(errorMessageFunction.apply(object));
    }
  }

  private static RlpString fromNumber(Number number) {
    if (number instanceof BigInteger) {
      return RlpString.create((BigInteger) number);
    } else if (number instanceof Long) {
      return RlpString.create((Long) number);
    } else if (number instanceof Integer) {
      return RlpString.create((Integer) number);
    } else {
      throw new RuntimeException(
          String.format("Couldn't serialize number %s : no serializer found.", number));
    }
  }

  private static RlpString fromBytesValue(Bytes bytes) {
    return RlpString.create(bytes.toArray());
  }

  public static class DecodedList {
    private final RlpList list;
    private final Bytes remainingData;

    public DecodedList(final RlpList list, final Bytes remainingData) {
      this.list = list;
      this.remainingData = remainingData;
    }

    public RlpList getList() {
      return list;
    }

    public Bytes getRemainingData() {
      return remainingData;
    }
  }
}
