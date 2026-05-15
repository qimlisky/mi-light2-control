from miio import Device
d = Device("ip", "token")
# 假设开关的 siid=2, piid=1，关闭（value=False）

# 功能 siid piid 数据类型 值范围       说明
# 开关	2	1	bool	True/False	你已经可以控制 ✅
# 亮度	2	2	uint8	1-100	    百分比，1最暗，100最亮
# 色温	2	3	uint32	2700-6500	单位开尔文(K)，2700暖光，6500冷光
# 模式	2	4	uint8	0-1	        0=普通模式，1=阅读模式（可能）
# d.send("set_properties", [{"siid": 2, "piid": 1, "value": True}])



# 一次查询三个属性：开关、亮度、色温
result = d.send("get_properties", [
    {"siid": 2, "piid": 1},   # 开关
    {"siid": 2, "piid": 2},   # 亮度
    {"siid": 2, "piid": 3}    # 色温
])
print("原始返回:")
print(result)

# 解析成可读格式
print("\n=== 台灯当前状态 ===")
for item in result:
    siid = item.get("siid")
    piid = item.get("piid")
    value = item.get("value")
    
    if siid == 2 and piid == 1:
        print(f"开关: {'开' if value else '关'}")
    elif siid == 2 and piid == 2:
        print(f"亮度: {value}%")
    elif siid == 2 and piid == 3:
        print(f"色温: {value}K")