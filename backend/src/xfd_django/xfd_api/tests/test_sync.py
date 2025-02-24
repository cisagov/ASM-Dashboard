"""Test sync."""

# Standard Python Libraries
from datetime import datetime
import secrets

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import User, UserType
from xfd_api.utils.csv_utils import create_checksum
from xfd_django.asgi import app

client = TestClient(app)


dummy_org_csv_data = """id,name,acronym,retired,created_at,updated_at,location,parent,children,sectors,cidrs
eaaa33cf-fe76-4b02-922f-18f80cdae158,Organization 2,ORG7,FALSE,2024-08-28T11:43:35,2024-03-07T02:43:38,"{'id': 'b50b00a5-c854-4f8e-8725-585056513d37', 'name': 'Location 2'}",,"[{'id': 'e44823d9-070e-44ca-95e9-1e9850e3fda4', 'name': 'Child Org 3'}]","[{'id': 'dc5f308b-b9ff-4ffa-af45-5d64ffb073f0', 'name': 'Sector 5'}, {'id': '275300ed-dc0d-4e8b-88de-47844b573d55', 'name': 'Sector 4'}, {'id': '5361b34e-26ed-468b-85ae-15e6487f56a3', 'name': 'Sector 2'}]","[{'id': '8499ddd8-8a35-4068-b6b1-ea2259ea106e', 'network': '182.215.202.115/31', 'start_ip': '182.215.202.115/32', 'end_ip': '182.215.202.115/32'}, {'id': '60aab3b3-b422-48ea-ac18-a6929c38ba40', 'network': '105.48.177.68/27', 'start_ip': '105.48.177.68/32', 'end_ip': '105.48.177.68/32'}, {'id': '305b6ba1-3c61-4492-96ab-67e5a2a1113a', 'network': '159.63.84.79/26', 'start_ip': '159.63.84.79/32', 'end_ip': '159.63.84.79/32'}]"
f7ce85fa-7e40-4a00-9fe3-777105fb3220,Organization 93,ORG60,TRUE,2021-01-02T10:00:24,2024-12-27T16:46:09,"{'id': 'fc4fd01d-6e39-4876-93c4-71e65aece0e9', 'name': 'Location 6'}",,"[{'id': 'a0ba2a32-a49d-41d8-a039-2536c7be66fe', 'name': 'Child Org 4'}, {'id': 'e22e4a9c-41b1-490c-a811-87252bc4760e', 'name': 'Child Org 4'}, {'id': '8b112ef9-3629-4c6f-b312-0a76f33038cb', 'name': 'Child Org 2'}]","[{'id': '51a445c6-5b57-46cb-ac4a-975342388d2c', 'name': 'Sector 5'}, {'id': 'be486aae-2b88-4bcc-8666-8ed64c975e75', 'name': 'Sector 4'}]","[{'id': '53349c50-03ab-4c99-9b63-fbf50455ca80', 'network': '87.205.162.147/28', 'start_ip': '87.205.162.147/32', 'end_ip': '87.205.162.147/32'}]"
2e1011e1-c7fb-4d3b-9ca5-25cc07bcf54c,Organization 43,ORG74,FALSE,2024-12-28T18:55:44,2022-08-06T21:15:13,"{'id': 'ce3c431a-1fef-42d9-9526-408abffda691', 'name': 'Location 3'}",,"[{'id': '54d6c863-1f53-4a94-8b66-8539c875b7af', 'name': 'Child Org 1'}, {'id': 'eb1037fc-efbe-49b6-8394-c86c26b20725', 'name': 'Child Org 3'}]","[{'id': 'a2f20434-9a9f-4d65-bc85-3cab06dcb37d', 'name': 'Sector 4'}, {'id': 'c977e414-4ef8-4de4-8bef-1c6aca1bc824', 'name': 'Sector 1'}]","[{'id': '0612bc12-a763-432f-b365-d2c1f2ff8168', 'network': '72.5.91.186/30', 'start_ip': '72.5.91.186/32', 'end_ip': '72.5.91.186/32'}, {'id': 'f494c3ce-7bc3-42ae-b707-3562fdb57ec5', 'network': '158.49.55.151/28', 'start_ip': '158.49.55.151/32', 'end_ip': '158.49.55.151/32'}, {'id': 'c788ad84-e33e-49af-9220-1db98f058d41', 'network': '4.86.220.109/32', 'start_ip': '4.86.220.109/32', 'end_ip': '4.86.220.109/32'}, {'id': '4f876396-146a-43dc-baea-024ffc1eb005', 'network': '239.68.27.235/31', 'start_ip': '239.68.27.235/32', 'end_ip': '239.68.27.235/32'}]"
0102d268-83bb-483d-9486-599f89753149,Organization 64,ORG59,FALSE,2023-02-11T14:51:45,2023-08-16T05:50:31,,"{'id': '2e332fbf-f721-4830-a293-9e6d53a7d84e', 'name': 'Parent Org 4'}",[],"[{'id': '14928444-4702-4dec-98ee-eef5a4f1848d', 'name': 'Sector 4'}, {'id': '4b095b5b-e379-423d-ae64-dc6fa6fb9b44', 'name': 'Sector 4'}, {'id': '7f53cd0d-3cc2-42e3-8127-db5d0d998c4a', 'name': 'Sector 2'}]","[{'id': 'f8378c86-8cc9-40dc-84da-9f9042689f6a', 'network': '180.201.252.16/32', 'start_ip': '180.201.252.16/32', 'end_ip': '180.201.252.16/32'}, {'id': 'da4fa77b-c04e-459b-9b1c-e36efbcf1a1b', 'network': '74.111.152.134/26', 'start_ip': '74.111.152.134/32', 'end_ip': '74.111.152.134/32'}, {'id': '959b324d-410a-4521-b1ef-cd5bbce2a392', 'network': '223.128.194.198/31', 'start_ip': '223.128.194.198/32', 'end_ip': '223.128.194.198/32'}, {'id': '402e11de-24b7-475d-bd73-1cca19d11ff6', 'network': '50.121.125.192/32', 'start_ip': '50.121.125.192/32', 'end_ip': '50.121.125.192/32'}, {'id': 'd999efa9-8830-4abe-bd85-101f06fccb4e', 'network': '10.149.157.208/30', 'start_ip': '10.149.157.208/32', 'end_ip': '10.149.157.208/32'}]"
6ad359be-8de8-4c27-9d7c-709cd74dd114,Organization 27,ORG58,FALSE,2020-07-28T16:53:34,2020-02-17T08:28:29,"{'id': 'dc8a160d-46a7-4511-b681-a3c466824d5a', 'name': 'Location 6'}","{'id': 'c3d0cb51-2888-4455-bf0f-d40e3d075a94', 'name': 'Parent Org 4'}","[{'id': 'b1c84f37-57c2-4920-9d1f-662d387085d2', 'name': 'Child Org 1'}]","[{'id': '659c92ea-4db1-4e23-9223-cebe4b82f8be', 'name': 'Sector 5'}, {'id': 'd3534992-71bf-4e26-bcbd-7b68a1794d6f', 'name': 'Sector 3'}]","[{'id': '37269d99-053b-4881-ba96-b0b9ccf487a8', 'network': '40.231.13.94/26', 'start_ip': '40.231.13.94/32', 'end_ip': '40.231.13.94/32'}, {'id': '01a05389-1c0f-4abc-b1b4-2f067a2948fe', 'network': '169.240.206.68/29', 'start_ip': '169.240.206.68/32', 'end_ip': '169.240.206.68/32'}, {'id': 'a0db6f70-28ce-4cc7-b09d-5a083456658a', 'network': '195.203.224.76/29', 'start_ip': '195.203.224.76/32', 'end_ip': '195.203.224.76/32'}]"
f51db5d7-fa1b-46b0-8b41-27a07044b53b,Organization 11,ORG17,FALSE,2023-01-18T02:11:53,2024-03-27T04:51:10,"{'id': '5a08037e-f1b2-4771-bc31-d787dbf8e61f', 'name': 'Location 5'}","{'id': '8d4c9eb3-db3f-48ad-97b6-47dc18c6b12f', 'name': 'Parent Org 10'}","[{'id': '67a3cdf8-919d-4191-8457-da056e4ff708', 'name': 'Child Org 1'}, {'id': 'c8c18b67-451e-4974-a410-ac2d04c1e044', 'name': 'Child Org 3'}]","[{'id': 'adedbfa1-cee0-4f98-bd87-85e1261b3935', 'name': 'Sector 5'}]","[{'id': 'e72ef159-643c-439b-83b4-9916ba5c7820', 'network': '208.41.185.8/28', 'start_ip': '208.41.185.8/32', 'end_ip': '208.41.185.8/32'}, {'id': 'c6f08ccc-2f76-4b25-b696-94c9364d25b8', 'network': '199.25.246.228/31', 'start_ip': '199.25.246.228/32', 'end_ip': '199.25.246.228/32'}, {'id': '2fdbacb1-4d22-451e-9239-b5776d66ce7f', 'network': '33.159.73.50/28', 'start_ip': '33.159.73.50/32', 'end_ip': '33.159.73.50/32'}]"
683466f2-c49f-4712-9732-ebdc6a180dfe,Organization 90,ORG100,FALSE,2021-09-26T13:48:34,2023-02-15T19:13:22,,,"[{'id': '3f445dfa-645e-41fe-840e-dedd1c3f5e05', 'name': 'Child Org 4'}, {'id': 'e1b1566b-a804-4fa5-baab-6d65451511be', 'name': 'Child Org 1'}, {'id': '8e60905f-f52f-4bed-a976-f1f93298879e', 'name': 'Child Org 3'}]","[{'id': '75bc6ecb-24a3-4a12-91d0-b7623a5dfff0', 'name': 'Sector 2'}, {'id': '5c296914-f169-4319-a284-da1fbb48a3ef', 'name': 'Sector 5'}]","[{'id': 'b8e48234-1ee2-42d7-8d33-e60ff7bfba19', 'network': '173.98.25.134/24', 'start_ip': '173.98.25.134/32', 'end_ip': '173.98.25.134/32'}]"
c033dc84-ea64-43eb-b700-7c446b351713,Organization 47,ORG6,TRUE,2021-06-14T03:57:07,2021-10-18T13:20:15,"{'id': '6e9df3e5-eabe-4740-adcf-6eabf5ee3883', 'name': 'Location 10'}",,"[{'id': '666c68e7-065e-48ae-a521-3fc1b72a329f', 'name': 'Child Org 5'}, {'id': 'b747fb25-b56e-443b-963f-fc32637714a9', 'name': 'Child Org 3'}]","[{'id': '950b3d88-84f2-43a3-a0e3-1406b0b6bf36', 'name': 'Sector 5'}]","[{'id': '1633a097-d234-4d5b-af83-126a39e2e586', 'network': '148.237.168.58/30', 'start_ip': '148.237.168.58/32', 'end_ip': '148.237.168.58/32'}]"
7d40ae2a-db93-4ec7-83d6-1d08fc6cce4d,Organization 79,ORG63,TRUE,2024-03-12T14:02:46,2021-04-12T07:47:15,"{'id': '51cf609b-ad6e-4e79-9703-245290f05ef6', 'name': 'Location 1'}",,"[{'id': 'e0227dec-f696-4ad7-b4b3-855a87bc645e', 'name': 'Child Org 2'}, {'id': '30c3fc05-40c9-4eac-9c19-b959e848e3de', 'name': 'Child Org 4'}]","[{'id': '3125b947-bb77-429b-a5ea-c126b9ca3c0d', 'name': 'Sector 2'}, {'id': '69e16f8d-1667-49ac-b140-4ab541c1b15e', 'name': 'Sector 1'}, {'id': 'a7c9bc64-111d-4a5d-a044-6f38933d0b06', 'name': 'Sector 5'}]","[{'id': '5a7e2e63-64fb-402b-9f02-70fae58550dc', 'network': '205.42.62.193/25', 'start_ip': '205.42.62.193/32', 'end_ip': '205.42.62.193/32'}, {'id': 'e3d6c220-6d01-472d-8b95-27993ee394d0', 'network': '39.236.252.95/31', 'start_ip': '39.236.252.95/32', 'end_ip': '39.236.252.95/32'}, {'id': 'f46c5acf-7b54-4bb7-a880-6e30d9a777b7', 'network': '105.179.203.163/30', 'start_ip': '105.179.203.163/32', 'end_ip': '105.179.203.163/32'}, {'id': '0d97a1cd-d26d-402c-a20a-5d095f76641a', 'network': '243.77.71.81/26', 'start_ip': '243.77.71.81/32', 'end_ip': '243.77.71.81/32'}]"
7e386d94-a788-49d2-942d-003debb99e5c,Organization 4,ORG55,TRUE,2020-02-29T00:47:15,2020-08-20T13:21:37,,"{'id': '2cbeb802-d5c6-4b66-a977-b676b848288c', 'name': 'Parent Org 4'}",[],"[{'id': '01839dc6-ccdc-4751-9c97-d2562cd423f6', 'name': 'Sector 5'}, {'id': '0b368087-be86-4f12-a29c-eb0b19327a51', 'name': 'Sector 4'}]","[{'id': 'e3580159-0428-4106-9b02-ceb52590269d', 'network': '154.52.254.0/24', 'start_ip': '154.52.254.0/32', 'end_ip': '154.52.254.0/32'}, {'id': '7cc8b6fb-452c-4713-ad38-84730d499567', 'network': '252.75.162.132/32', 'start_ip': '252.75.162.132/32', 'end_ip': '252.75.162.132/32'}, {'id': '4ed089e5-9bfa-44cf-a50f-d961a905be23', 'network': '185.91.179.113/29', 'start_ip': '185.91.179.113/32', 'end_ip': '185.91.179.113/32'}, {'id': '8a8edd95-4bb6-4017-97be-d7774ec59ac1', 'network': '174.5.60.2/27', 'start_ip': '174.5.60.2/32', 'end_ip': '174.5.60.2/32'}, {'id': '057ef0c7-d3a8-4ad3-af5a-6adb32b6b5e5', 'network': '123.24.215.151/30', 'start_ip': '123.24.215.151/32', 'end_ip': '123.24.215.151/32'}]"
"""


# Test: post valid data with invalid checksum should return 500
@pytest.mark.django_db(transaction=True)
def test_sync_invalid_checksum_should_return_500():
    """Test sync with invalid checksum."""
    user = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    invalid_checksum = create_checksum(dummy_org_csv_data + "invalid")
    response = client.post(
        "/sync",
        json={"data": dummy_org_csv_data},
        headers={
            "x-checksum": invalid_checksum,
            "Authorization": "Bearer {}".format(create_jwt_token(user)),
        },
    )
    assert response.status_code == 500


# Test: post valid data with missing checksum should return 500
# @pytest.mark.django_db(transaction=True)
# def test_synd_missing_checksum_should_return_500():
#     user = user = User.objects.create(
#         firstName="first",
#         lastName="last",
#         email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
#         userType=UserType.STANDARD,
#         createdAt=datetime.now(),
#         updatedAt=datetime.now(),
#     )
#     headers = {
#         "Authorization": "Bearer {}".format(create_jwt_token(user))
#     }
#     response = client.post("/sync", json={"data": dummy_org_csv_data}, headers=headers)
#     assert response.status_code == 500


# Test: post empty data should return 500
