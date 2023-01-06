from dataclasses import dataclass, asdict
from enum import Enum
from typing import Generator, Optional, List, Tuple
import pprint


# Названия полей в классах и enum'ах почти полностью соответствуют описаниям в ГОСТ Р 54619-2011.


class PacketType(Enum):
    """Тип пакета протокола транспортного уровня."""

    EGTS_PT_RESPONSE = 0
    EGTS_РТ_APPDATA = 1
    EGTS_РТ_SIGNED_APPDATA = 2


@dataclass
class ServicesFrameData:
    """Базовый класс SFRD (Services Frame Data) — структуры данных, зависящей от типа пакета и содержащей информацию протокола уровня поддержки услуг.

    Структуры конкретных типов наследуются от этого класса. Пока реализован только тип AppData."""

    check_sum: int


@dataclass
class Transport:
    """Пакет протокола транспортного уровня."""

    protocol_version: int
    security_key_id: int

    prefix: int
    route: int
    encryption_algorithm: int
    compressed: bool
    priority: int

    header_length: int
    header_encoding: int
    frame_data_length: int
    packet_identifier: int
    packet_type: PacketType

    peer_address: Optional[int]
    recipient_address: Optional[int]
    time_to_live: Optional[int]

    header_check_sum: int
    services_frame_data: Optional[ServicesFrameData]


@dataclass
class SubrecordData:
    """Данные подзаписи уровня поддержки услуг (базовый класс). 
    Наполнение данного поля специфично для каждого сочетания идентификатора сервиса и типа подзаписи."""

    pass


@dataclass
class DummySubrecord(SubrecordData):
    """Класс-заглушка для неподдерживаемых (пока что) подзаписей уровня поддержки услуг."""

    data: bytes


@dataclass
class TermIdentity(SubrecordData):
    """Формат подзаписи EGTS_SR_TERM_IDENTITY сервиса EGTS_AUTH_SERVICE."""

    terminal_identifier: int
    ssra: bool

    home_dispatcher_identifier: Optional[int]
    international_mobile_equipment_identity: Optional[str]
    international_mobile_subscriber_identity: Optional[str]
    language_code: Optional[str]
    network_identifier: Optional[bytes]
    buffer_size: Optional[int]
    mobile_station_integrated_services_digital_network_number: Optional[str]


class SubrecordType(Enum):
    """Тип подзаписи уровня поддержки услуг."""

    EGTS_SR_RECORD_RESPONSE = 0

    # Авторизация (ГОСТ Р 54619)
    EGTS_SR_TERM_IDENTITY = 1
    EGTS_SR_MODULE_DATA = 2
    EGTS_SR_VEHICLE_DATA = 3
    EGTS_SR_AUTH_PARAMS = 6
    EGTS_SR_AUTH_INFO = 7
    EGTS_SR_SERVICE_INFO = 8
    EGTS_SR_RESULT_CODE = 9

    # Данные (Приказ №285)
    EGTS_SR_POS_DATA = 16
    EGTS_SR_EXT_POS_DATA = 17
    EGTS_SR_AD_SENSORS_DATA = 18
    EGTS_SR_COUNTERS_DATA = 19
    EGTS_SR_STATE_DATA = 20
    EGTS_SR_LOOPIN_DATA = 22
    EGTS_SR_ABS_DIG_SENS_DATA = 23
    EGTS_SR_ABS_AN_SENS_DATA = 24
    EGTS_SR_ABS_CNTR_DATA = 25
    EGTS_SR_ABS_LOOPIN_DATA = 26
    EGTS_SR_LIQUID_LEVEL_SENSOR = 27
    EGTS_SR_PASSENGERS_COUNTERS = 28


@dataclass
class Subrecord:
    """Подзапись протокола уровня поддержки услуг."""

    type: SubrecordType
    length: int
    data: Optional[SubrecordData]


@dataclass
class ServiceDataRecord:
    """Запись протокола уровня поддержки услуг."""

    record_length: int
    record_number: int

    source_service_on_device: bool
    recipient_service_on_device: bool
    record_processing_priority: int

    object_identifier: Optional[int]
    event_identifier: Optional[int]
    time: Optional[int]

    source_service_type: int
    recipient_service_type: int

    subrecords: List[Subrecord]


@dataclass
class AppData(ServicesFrameData):
    """SFRD для пакета типа EGTS_PT_APPDATA."""

    service_data_records: List[ServiceDataRecord]


# Вспомогательные функции для получения значений соответствующих типов из набора байтов.
# Функции принимают байты и возвращают пару из значения и оставшихся байтов.
# Размеры типов, кодировки и т.п. описаны в ГОСТ Р 54619-2011.

def byte(data: bytes) -> Tuple[int, bytes]:
    return data[0], data[1:]


def ushort(data: bytes) -> Tuple[int, bytes]:
    return int.from_bytes(data[:2], byteorder='little'), data[2:]


def uint(data: bytes) -> Tuple[int, bytes]:
    return int.from_bytes(data[:4], byteorder='little'), data[4:]


def string(data: bytes, length: int) -> Tuple[str, bytes]:
    return data[:length].decode('cp1251'), data[length:]


def binary(data: bytes, length: int) -> Tuple[str, bytes]:
    return data[:length], data[length:]


def parse_term_identity(data: bytes) -> TermIdentity:
    """Парсер подзаписи типа EGTS_SR_TERM_IDENTITY сервиса EGTS_AUTH_SERVICE."""

    tid, data = uint(data)
    flags, data = byte(data)

    # Достаём биты из байта flags с помощью битовой арифметики.
    # Сдвигаем побитово до нужного места в байте, а затем побитовым AND обнуляем ненужные ведущие биты.
    # Почитать про битовые операции в Python можно здесь: https://docs.python.org/3/library/stdtypes.html#bitwise-operations-on-integer-types
    hdid_exists = flags >> 7 & 0b1
    imei_exists = flags >> 6 & 0b1
    imsi_exists = flags >> 5 & 0b1
    lngc_exists = flags >> 4 & 0b1
    ssra = bool(flags >> 3 & 0b1)
    nid_exists = flags >> 2 & 0b1
    bs_exists = flags >> 1 & 0b1
    mn_exists = flags & 0b1

    hdid = imei = imsi = lngc = nid = bs = msisdn = None
    if hdid_exists:
        hdid, data = ushort(data)
    if imei_exists:
        imei, data = string(data, 15)
    if imsi_exists:
        imsi, data = string(data, 16)
    if lngc_exists:
        lngc, data = string(data, 3)
    if nid_exists:
        nid, data = binary(data, 3)
    if bs_exists:
        bs, data = ushort(data)
    if mn_exists:
        msisdn, data = string(data, 15)

    return TermIdentity(terminal_identifier=tid,
                        ssra=ssra,
                        home_dispatcher_identifier=hdid,
                        international_mobile_equipment_identity=imei,
                        international_mobile_subscriber_identity=imsi,
                        language_code=lngc,
                        network_identifier=nid,
                        buffer_size=bs,
                        mobile_station_integrated_services_digital_network_number=msisdn)


def parse_subrecords(data: bytes) -> Generator[Subrecord, None, None]:
    """Парсер подзаписей уровня поддержки услуг."""

    while data:
        srt, data = byte(data)
        subrecord_type = SubrecordType(srt)
        srl, data = ushort(data)
        if srl:
            srd, data = binary(data, srl)

            # TODO: здесь надо дописать elif-ветки для остальных типов подзаписей и
            # вызвать в них соответствующие парсеры (их тоже надо дописать)
            if subrecord_type == SubrecordType.EGTS_SR_TERM_IDENTITY:
                subrecord_data = parse_term_identity(srd)
            else:
                subrecord_data = DummySubrecord(srd)
        else:
            subrecord_data = None

        yield Subrecord(type=subrecord_type,
                        length=srl,
                        data=subrecord_data)


def parse_service_data_records(data: bytes) -> Generator[ServiceDataRecord, None, None]:
    """Парсер записей уровня поддержки услуг."""

    while data:
        rl, data = ushort(data)
        rn, data = ushort(data)
        flags, data = byte(data)

        ssod = bool(flags >> 7 & 0b1)
        rsod = bool(flags >> 6 & 0b1)
        rpp = flags >> 3 & 0b111
        tmfe = bool(flags >> 2 & 0b1)
        evfe = bool(flags >> 1 & 0b1)
        obfe = bool(flags & 0b1)

        oid = evid = tm = None
        if obfe:
            oid, data = uint(data)
        if evfe:
            evid, data = uint(data)
        if tmfe:
            tm, data = uint(data)

        sst, data = byte(data)
        rst, data = byte(data)
        rd, data = binary(data, rl)

        yield ServiceDataRecord(record_length=rl,
                                record_number=rn,
                                source_service_on_device=ssod, recipient_service_on_device=rsod,
                                record_processing_priority=rpp,
                                object_identifier=oid,
                                event_identifier=evid,
                                time=tm,
                                source_service_type=sst,
                                recipient_service_type=rst,
                                subrecords=list(parse_subrecords(rd)))


def parse_service_frame_data(data: bytes, check_sum: int, packet_type: PacketType) -> ServicesFrameData:
    """Парсер SFRD."""

    if packet_type == PacketType.EGTS_РТ_APPDATA:
        return AppData(check_sum=check_sum,
                       service_data_records=list(parse_service_data_records(data)))

    # TODO: здесь надо дописать if-ветки для остальных типов пакетов

    return ServicesFrameData(check_sum=check_sum)


def parse_transport(data: bytes) -> Transport:
    """Парсер пакета протокола транспортного уровня."""

    prv, skid, flags, hl, he, *data = data
    data = bytes(data)

    prf = flags >> 6 & 0b11
    rte = flags >> 5 & 0b1
    ena = flags >> 3 & 0b11
    cmp = bool(flags >> 2 & 0b1)
    pr = flags & 0b11

    fdl, data = ushort(data)
    pid, data = ushort(data)
    pt, data = byte(data)
    packet_type = PacketType(pt)

    if rte:
        pra, data = ushort(data)
        rca, data = ushort(data)
        ttl, data = byte(data)
    else:
        pra = rca = ttl = None

    hcs, data = byte(data)

    if fdl:
        sfrd, data = binary(data, fdl)
        sfrcs, data = ushort(data)
        services_frame_data = parse_service_frame_data(data=sfrd, check_sum=sfrcs, packet_type=packet_type)
    else:
        services_frame_data = None

    return Transport(protocol_version=prv,
                     security_key_id=skid,
                     prefix=prf, route=rte, encryption_algorithm=ena, compressed=cmp, priority=pr,
                     header_length=hl,
                     header_encoding=he,
                     frame_data_length=fdl,
                     packet_identifier=pid,
                     packet_type=packet_type,
                     peer_address=pra, recipient_address=rca, time_to_live=ttl,
                     header_check_sum=hcs,
                     services_frame_data=services_frame_data)


if __name__ == '__main__':
    # Пример пакета EGTS
    data = b'\x01\x00\x02\x0b\x00$\x00\x01\x00\x01\x16\x19\x00\x01\x00\x91\xf4\xc4\r\x00\x01\x01\x01\x16\x00\xf4\xc4\r\x00B862531049023881\xb4\x05g\x14'

    # Запускаем наш парсер на тестовом пакете
    egts = parse_transport(data)

